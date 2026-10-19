/*
Copyright 2026 The KubeFleet Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package authorization

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	authenticationv1 "k8s.io/api/authentication/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	placementv1beta1 "github.com/kubefleet-dev/kubefleet/apis/placement/v1beta1"
	"github.com/kubefleet-dev/kubefleet/pkg/utils"
	"github.com/kubefleet-dev/kubefleet/pkg/utils/informer"
	"github.com/kubefleet-dev/kubefleet/pkg/utils/resourceeligibility"
	testinformer "github.com/kubefleet-dev/kubefleet/test/utils/informer"
)

const (
	firstConfigMapName  = "first"
	testApp             = "app"
	testPlacementName   = "placement"
	testRequester       = "requester"
	getVerb             = "get"
	listVerb            = "list"
	selectedLabelValue  = "selected"
	testNamespace       = "team"
	testClusterRoleName = "reader"
	testUnknownValue    = "Unknown"
)

type unsupportedPlacement struct {
	placementv1beta1.PlacementObj
}

func placementTestMapper() *meta.DefaultRESTMapper {
	mapper := meta.NewDefaultRESTMapper([]schema.GroupVersion{corev1.SchemeGroupVersion, rbacv1.SchemeGroupVersion})
	for _, kind := range []string{utils.ConfigMapKind, "Secret"} {
		mapper.Add(corev1.SchemeGroupVersion.WithKind(kind), meta.RESTScopeNamespace)
	}
	mapper.Add(utils.NamespaceGVK, meta.RESTScopeRoot)
	mapper.Add(rbacv1.SchemeGroupVersion.WithKind("ClusterRole"), meta.RESTScopeRoot)
	return mapper
}

func TestNewPlacementAuthorizer(t *testing.T) {
	reader := fake.NewClientBuilder().Build()
	mapper := placementTestMapper()
	reviewer, err := NewReviewer(&fakeSubjectAccessReviewClient{}, mapper, 1)
	if err != nil {
		t.Fatal(err)
	}
	inventory := &testinformer.FakeManager{}
	checker := resourceeligibility.AllowAll(mapper)
	tests := []struct {
		name      string
		reader    client.Reader
		mapper    meta.RESTMapper
		reviewer  *Reviewer
		inventory informer.Manager
		checker   resourceeligibility.Checker
		wantErr   string
	}{
		{name: "valid", reader: reader, mapper: mapper, reviewer: reviewer, inventory: inventory, checker: checker},
		{name: "missing reader", mapper: mapper, reviewer: reviewer, inventory: inventory, checker: checker, wantErr: "resource reader must not be nil"},
		{name: "missing REST mapper", reader: reader, reviewer: reviewer, inventory: inventory, checker: checker, wantErr: "REST mapper must not be nil"},
		{name: "missing reviewer", reader: reader, mapper: mapper, inventory: inventory, checker: checker, wantErr: "authorization reviewer must not be nil"},
		{name: "missing resource informer", reader: reader, mapper: mapper, reviewer: reviewer, checker: checker, wantErr: "resource informer must not be nil"},
		{name: "missing eligibility checker", reader: reader, mapper: mapper, reviewer: reviewer, inventory: inventory, wantErr: "resource eligibility checker must not be nil"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewPlacementAuthorizer(tt.reader, tt.mapper, tt.reviewer, tt.inventory, tt.checker)
			if tt.wantErr != "" {
				if got != nil || err == nil || err.Error() != tt.wantErr {
					t.Fatalf("NewPlacementAuthorizer() = (%v, %v), want (nil, %q)", got, err, tt.wantErr)
				}
				return
			}
			if got == nil || err != nil {
				t.Fatalf("NewPlacementAuthorizer() = (%v, %v), want initialized authorizer and nil error", got, err)
			}
			if result := got.Authorize(context.Background(), authenticationv1.UserInfo{Username: testRequester}, &placementv1beta1.ResourcePlacement{ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace}}); result.Decision != DecisionAllowed || result.Err != nil || result.DenialReason != "" {
				t.Errorf("Authorize() = %+v, want allowed with no selections", result)
			}
		})
	}
}

func TestPlacementAuthorizeUninitialized(t *testing.T) {
	for name, authorizer := range map[string]*PlacementAuthorizer{"nil": nil, "zero value": {}} {
		t.Run(name, func(t *testing.T) {
			result := authorizer.Authorize(context.Background(), authenticationv1.UserInfo{}, &placementv1beta1.ResourcePlacement{})
			if result.Decision != DecisionIndeterminate || result.Err == nil {
				t.Errorf("Authorize() = %+v, want initialization error", result)
			}
		})
	}
}

func TestPlacementAuthorizeSelections(t *testing.T) {
	nsGVR := corev1.SchemeGroupVersion.WithResource("namespaces")
	cmGVR := corev1.SchemeGroupVersion.WithResource("configmaps")
	secretGVR := corev1.SchemeGroupVersion.WithResource("secrets")
	clusterRoleGVR := rbacv1.SchemeGroupVersion.WithResource("clusterroles")
	namedClusterRole := placementv1beta1.ResourceSelectorTerm{Group: rbacv1.GroupName, Version: "v1", Kind: "ClusterRole", Name: testClusterRoleName}
	allClusterRoles := namedClusterRole
	allClusterRoles.Name = ""
	labeledClusterRoles := allClusterRoles
	labeledClusterRoles.LabelSelector = &metav1.LabelSelector{MatchLabels: map[string]string{testApp: selectedLabelValue}}
	namedCM := placementv1beta1.ResourceSelectorTerm{Version: "v1", Kind: utils.ConfigMapKind, Name: firstConfigMapName}
	allCM := placementv1beta1.ResourceSelectorTerm{Version: "v1", Kind: utils.ConfigMapKind}
	labelCM := allCM
	labelCM.LabelSelector = &metav1.LabelSelector{MatchLabels: map[string]string{testApp: selectedLabelValue}}
	namespaceSelector := func(scope placementv1beta1.SelectionScope) placementv1beta1.ResourceSelectorTerm {
		return placementv1beta1.ResourceSelectorTerm{Version: "v1", Kind: utils.NamespaceGVK.Kind, Name: testNamespace, SelectionScope: scope}
	}
	labeledExpandedNamespace := namespaceSelector(placementv1beta1.NamespaceWithResources)
	labeledExpandedNamespace.Name = ""
	labeledExpandedNamespace.LabelSelector = &metav1.LabelSelector{MatchLabels: map[string]string{testApp: selectedLabelValue}}
	allExpandedNamespaces := namespaceSelector(placementv1beta1.NamespaceWithResources)
	allExpandedNamespaces.Name = ""
	listCM := resourceAttributes(cmGVR, listVerb, testNamespace, "")
	getFirst := resourceAttributes(cmGVR, getVerb, testNamespace, firstConfigMapName)
	getNS := resourceAttributes(nsGVR, getVerb, "", testNamespace)
	getClusterRole := resourceAttributes(clusterRoleGVR, getVerb, "", testClusterRoleName)
	listClusterRoles := resourceAttributes(clusterRoleGVR, listVerb, "", "")
	namespaceContentsChecks := []authorizationv1.ResourceAttributes{listCM, resourceAttributes(secretGVR, listVerb, testNamespace, "")}
	expandedNamespaceChecks := append([]authorizationv1.ResourceAttributes{getNS}, namespaceContentsChecks...)
	tests := []struct {
		name      string
		namespace string
		selectors []placementv1beta1.ResourceSelectorTerm
		want      []authorizationv1.ResourceAttributes
	}{
		{name: "RP named", namespace: testNamespace, selectors: []placementv1beta1.ResourceSelectorTerm{namedCM}, want: []authorizationv1.ResourceAttributes{getFirst}},
		{name: "RP label", namespace: testNamespace, selectors: []placementv1beta1.ResourceSelectorTerm{labelCM}, want: []authorizationv1.ResourceAttributes{listCM}},
		{name: "RP all of kind", namespace: testNamespace, selectors: []placementv1beta1.ResourceSelectorTerm{allCM}, want: []authorizationv1.ResourceAttributes{listCM}},
		{name: "CRP named cluster resource", selectors: []placementv1beta1.ResourceSelectorTerm{namedClusterRole}, want: []authorizationv1.ResourceAttributes{getClusterRole}},
		{name: "CRP labeled cluster resources", selectors: []placementv1beta1.ResourceSelectorTerm{labeledClusterRoles}, want: []authorizationv1.ResourceAttributes{listClusterRoles}},
		{name: "CRP all cluster resources of kind", selectors: []placementv1beta1.ResourceSelectorTerm{allClusterRoles}, want: []authorizationv1.ResourceAttributes{listClusterRoles}},
		{name: "overlapping selectors deduplicate checks", namespace: testNamespace, selectors: []placementv1beta1.ResourceSelectorTerm{allCM, labelCM, namedCM, allCM}, want: []authorizationv1.ResourceAttributes{listCM, getFirst}},
		{name: "namespace only", selectors: []placementv1beta1.ResourceSelectorTerm{namespaceSelector(placementv1beta1.NamespaceOnly)}, want: []authorizationv1.ResourceAttributes{getNS}},
		{name: "cluster resource before namespace only", selectors: []placementv1beta1.ResourceSelectorTerm{namedClusterRole, namespaceSelector(placementv1beta1.NamespaceOnly)}, want: []authorizationv1.ResourceAttributes{getNS, getClusterRole}},
		{name: "namespace with named resource selectors", selectors: []placementv1beta1.ResourceSelectorTerm{namedCM, namespaceSelector(placementv1beta1.NamespaceWithResourceSelectors)}, want: []authorizationv1.ResourceAttributes{getNS, getFirst}},
		{name: "namespace before named resource selector", selectors: []placementv1beta1.ResourceSelectorTerm{namespaceSelector(placementv1beta1.NamespaceWithResourceSelectors), namedCM}, want: []authorizationv1.ResourceAttributes{getNS, getFirst}},
		{name: "namespace with label resource selectors", selectors: []placementv1beta1.ResourceSelectorTerm{namespaceSelector(placementv1beta1.NamespaceWithResourceSelectors), labelCM}, want: []authorizationv1.ResourceAttributes{getNS, listCM}},
		{name: "selective namespace permits cluster resources without namespace", selectors: []placementv1beta1.ResourceSelectorTerm{namespaceSelector(placementv1beta1.NamespaceWithResourceSelectors), namedCM, namedClusterRole}, want: []authorizationv1.ResourceAttributes{getNS, getFirst, getClusterRole}},
		{name: "selective namespace after mixed resource selectors", selectors: []placementv1beta1.ResourceSelectorTerm{namedClusterRole, namedCM, namespaceSelector(placementv1beta1.NamespaceWithResourceSelectors)}, want: []authorizationv1.ResourceAttributes{getNS, getFirst, getClusterRole}},
		{name: "namespace with resources", selectors: []placementv1beta1.ResourceSelectorTerm{namespaceSelector(placementv1beta1.NamespaceWithResources)}, want: expandedNamespaceChecks},
		{name: "default namespace expansion", selectors: []placementv1beta1.ResourceSelectorTerm{namespaceSelector("")}, want: expandedNamespaceChecks},
		{name: "labeled namespace expansion", selectors: []placementv1beta1.ResourceSelectorTerm{labeledExpandedNamespace}, want: append([]authorizationv1.ResourceAttributes{resourceAttributes(nsGVR, listVerb, "", "")}, namespaceContentsChecks...)},
		{name: "all namespaces expansion", selectors: []placementv1beta1.ResourceSelectorTerm{allExpandedNamespaces}, want: append([]authorizationv1.ResourceAttributes{resourceAttributes(nsGVR, listVerb, "", "")}, namespaceContentsChecks...)},
		{name: "cluster resource before expanded namespace", selectors: []placementv1beta1.ResourceSelectorTerm{namedClusterRole, namespaceSelector(placementv1beta1.NamespaceWithResources)}, want: append([]authorizationv1.ResourceAttributes{getClusterRole}, expandedNamespaceChecks...)},
		{name: "cluster label selector", selectors: []placementv1beta1.ResourceSelectorTerm{{Version: "v1", Kind: utils.NamespaceGVK.Kind, SelectionScope: placementv1beta1.NamespaceOnly, LabelSelector: &metav1.LabelSelector{MatchLabels: map[string]string{testApp: selectedLabelValue}}}}, want: []authorizationv1.ResourceAttributes{resourceAttributes(nsGVR, listVerb, "", "")}},
		{name: "cluster all of kind", selectors: []placementv1beta1.ResourceSelectorTerm{{Version: "v1", Kind: utils.NamespaceGVK.Kind, SelectionScope: placementv1beta1.NamespaceOnly}}, want: []authorizationv1.ResourceAttributes{resourceAttributes(nsGVR, listVerb, "", "")}},
		{name: "empty match still requires list", namespace: "empty", selectors: []placementv1beta1.ResourceSelectorTerm{allCM}, want: []authorizationv1.ResourceAttributes{resourceAttributes(cmGVR, listVerb, "empty", "")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mapper := placementTestMapper()
			scheme := runtime.NewScheme()
			if err := corev1.AddToScheme(scheme); err != nil {
				t.Fatal(err)
			}
			reader := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: testNamespace, Labels: map[string]string{testApp: selectedLabelValue}}},
			).WithInterceptorFuncs(interceptor.Funcs{
				Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
					if _, ok := obj.(*corev1.Namespace); !ok {
						return fmt.Errorf("unexpected source object read: %T", obj)
					}
					return c.Get(ctx, key, obj, opts...)
				},
				List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
					if _, ok := list.(*corev1.NamespaceList); !ok {
						return fmt.Errorf("unexpected source collection read: %T", list)
					}
					return c.List(ctx, list, opts...)
				},
			}).Build()
			var mu sync.Mutex
			var got []authorizationv1.ResourceAttributes
			reviewer, err := NewReviewer(&fakeSubjectAccessReviewClient{create: func(_ context.Context, review *authorizationv1.SubjectAccessReview) error {
				mu.Lock()
				defer mu.Unlock()
				got = append(got, *review.Spec.ResourceAttributes)
				review.Status.Allowed = true
				return nil
			}}, mapper, DefaultMaxConcurrentReviews)
			if err != nil {
				t.Fatal(err)
			}
			inventory := &testinformer.FakeManager{NamespaceScopedResources: []schema.GroupVersionResource{cmGVR, secretGVR}}
			a, err := NewPlacementAuthorizer(reader, mapper, reviewer, inventory, resourceeligibility.AllowAll(mapper))
			if err != nil {
				t.Fatal(err)
			}
			var placement placementv1beta1.PlacementObj
			spec := placementv1beta1.PlacementSpec{ResourceSelectors: tt.selectors}
			if tt.namespace == "" {
				placement = &placementv1beta1.ClusterResourcePlacement{ObjectMeta: metav1.ObjectMeta{Name: testPlacementName}, Spec: spec}
			} else {
				placement = &placementv1beta1.ResourcePlacement{ObjectMeta: metav1.ObjectMeta{Name: testPlacementName, Namespace: tt.namespace}, Spec: spec}
			}
			result := a.Authorize(context.Background(), authenticationv1.UserInfo{Username: testRequester}, placement)
			if result.Decision != DecisionAllowed || result.Err != nil || result.DenialReason != "" {
				t.Fatalf("Authorize() = %+v, want allowed", result)
			}
			if diff := cmp.Diff(tt.want, got, cmpopts.SortSlices(func(a, b authorizationv1.ResourceAttributes) bool {
				return fmt.Sprint(a) < fmt.Sprint(b)
			})); diff != "" {
				t.Errorf("Authorize() checks mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestPlacementAuthorizePlacementTypesAndScope(t *testing.T) {
	const selectiveNamespaceErr = "requires one named namespace"
	namedNamespace := placementv1beta1.ResourceSelectorTerm{Version: "v1", Kind: utils.NamespaceGVK.Kind, Name: testNamespace, SelectionScope: placementv1beta1.NamespaceOnly}
	selectiveNamespace := namedNamespace
	selectiveNamespace.SelectionScope = placementv1beta1.NamespaceWithResourceSelectors
	unnamedSelectiveNamespace := selectiveNamespace
	unnamedSelectiveNamespace.Name = ""
	labeledSelectiveNamespace := selectiveNamespace
	labeledSelectiveNamespace.LabelSelector = &metav1.LabelSelector{}
	unsupportedScope := namedNamespace
	unsupportedScope.SelectionScope = testUnknownValue
	namedConfigMap := placementv1beta1.ResourceSelectorTerm{Version: "v1", Kind: utils.ConfigMapKind, Name: firstConfigMapName}
	clusterPlacement := func(selectors ...placementv1beta1.ResourceSelectorTerm) *placementv1beta1.ClusterResourcePlacement {
		return &placementv1beta1.ClusterResourcePlacement{Spec: placementv1beta1.PlacementSpec{ResourceSelectors: selectors}}
	}
	resourcePlacement := func(selectors ...placementv1beta1.ResourceSelectorTerm) *placementv1beta1.ResourcePlacement {
		return &placementv1beta1.ResourcePlacement{ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace}, Spec: placementv1beta1.PlacementSpec{ResourceSelectors: selectors}}
	}
	tests := []struct {
		name      string
		placement placementv1beta1.PlacementObj
		wantErr   string
	}{
		{name: "nil placement", wantErr: "unsupported placement type"},
		{name: "typed nil RP", placement: (*placementv1beta1.ResourcePlacement)(nil), wantErr: "resource placement must not be nil"},
		{name: "typed nil CRP", placement: (*placementv1beta1.ClusterResourcePlacement)(nil), wantErr: "cluster resource placement must not be nil"},
		{name: "unsupported placement implementation", placement: &unsupportedPlacement{}, wantErr: "unsupported placement type"},
		{name: "RP without namespace is not a CRP", placement: &placementv1beta1.ResourcePlacement{}, wantErr: "resource placement must specify a namespace"},
		{name: "CRP with namespace is not an RP", placement: &placementv1beta1.ClusterResourcePlacement{ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace}}, wantErr: "cluster resource placement must not specify a namespace"},
		{name: "RP cannot select Namespace", placement: resourcePlacement(namedNamespace), wantErr: "cannot select cluster-scoped resource"},
		{name: "RP cannot use selective namespace mode", placement: resourcePlacement(selectiveNamespace, namedConfigMap), wantErr: "cannot select cluster-scoped resource"},
		{name: "CRP requires selective namespace for namespaced resources", placement: clusterPlacement(namedConfigMap), wantErr: "requires NamespaceWithResourceSelectors"},
		{name: "NamespaceOnly cannot scope namespaced selectors", placement: clusterPlacement(namedNamespace, namedConfigMap), wantErr: "requires NamespaceWithResourceSelectors"},
		{name: "selective namespace must have a name", placement: clusterPlacement(unnamedSelectiveNamespace, namedConfigMap), wantErr: selectiveNamespaceErr},
		{name: "selective namespace cannot have a label selector", placement: clusterPlacement(labeledSelectiveNamespace, namedConfigMap), wantErr: selectiveNamespaceErr},
		{name: "multiple selective namespaces rejected", placement: clusterPlacement(selectiveNamespace, selectiveNamespace), wantErr: selectiveNamespaceErr},
		{name: "unsupported namespace scope rejected", placement: clusterPlacement(unsupportedScope), wantErr: "unsupported namespace selection scope"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mapper := placementTestMapper()
			reader := fake.NewClientBuilder().WithObjects(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: testNamespace}}).Build()
			var calls int
			reviewer, err := NewReviewer(&fakeSubjectAccessReviewClient{create: func(context.Context, *authorizationv1.SubjectAccessReview) error {
				calls++
				return errors.New("unexpected SubjectAccessReview")
			}}, mapper, 1)
			if err != nil {
				t.Fatal(err)
			}
			a, err := NewPlacementAuthorizer(reader, mapper, reviewer, &testinformer.FakeManager{}, resourceeligibility.AllowAll(mapper))
			if err != nil {
				t.Fatal(err)
			}
			result := a.Authorize(context.Background(), authenticationv1.UserInfo{Username: testRequester}, tt.placement)
			if result.Decision != DecisionIndeterminate || result.Err == nil || !strings.Contains(result.Err.Error(), tt.wantErr) {
				t.Errorf("Authorize() = %+v, want indeterminate decision with error containing %q", result, tt.wantErr)
			}
			if calls != 0 {
				t.Errorf("Authorize() SubjectAccessReview calls = %d, want 0", calls)
			}
		})
	}
}

func TestPlacementAuthorizeFailures(t *testing.T) {
	tests := []struct {
		name   string
		modify func(*PlacementAuthorizer, *placementv1beta1.ResourcePlacement)
		denied bool
	}{
		{name: "missing dependencies", modify: func(a *PlacementAuthorizer, _ *placementv1beta1.ResourcePlacement) { a.reader = nil }},
		{name: "unknown kind", modify: func(_ *PlacementAuthorizer, p *placementv1beta1.ResourcePlacement) {
			p.Spec.ResourceSelectors[0].Kind = testUnknownValue
		}},
		{name: "name and label selector are mutually exclusive", modify: func(_ *PlacementAuthorizer, p *placementv1beta1.ResourcePlacement) {
			p.Spec.ResourceSelectors[0].LabelSelector = &metav1.LabelSelector{}
		}},
		{name: "invalid label selector", modify: func(_ *PlacementAuthorizer, p *placementv1beta1.ResourcePlacement) {
			p.Spec.ResourceSelectors[0].Name = ""
			p.Spec.ResourceSelectors[0].LabelSelector = &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: testApp, Operator: "invalid"}}}
		}},
		{name: "RP cluster resource", modify: func(_ *PlacementAuthorizer, p *placementv1beta1.ResourcePlacement) {
			p.Spec.ResourceSelectors[0].Kind = utils.NamespaceGVK.Kind
		}},
		{name: "RP missing namespace", modify: func(_ *PlacementAuthorizer, p *placementv1beta1.ResourcePlacement) { p.Namespace = "" }},
		{name: "namespace not eligible", modify: func(a *PlacementAuthorizer, _ *placementv1beta1.ResourcePlacement) {
			a.resourceEligibilityChecker.SetNamespaceCheckList(resourceeligibility.NamespaceEligibilityModeDenyList, []string{testNamespace}, nil)
		}},
		{name: "SAR API failure", modify: func(a *PlacementAuthorizer, _ *placementv1beta1.ResourcePlacement) {
			a.reviewer.client = &fakeSubjectAccessReviewClient{create: func(context.Context, *authorizationv1.SubjectAccessReview) error {
				return errors.New("SAR unavailable")
			}}
		}},
		{name: "get denied", denied: true, modify: func(a *PlacementAuthorizer, _ *placementv1beta1.ResourcePlacement) {
			a.reviewer.client = &fakeSubjectAccessReviewClient{create: func(_ context.Context, review *authorizationv1.SubjectAccessReview) error {
				review.Status.Denied = true
				return nil
			}}
		}},
		{name: "list denied even with no matches", denied: true, modify: func(a *PlacementAuthorizer, p *placementv1beta1.ResourcePlacement) {
			p.Namespace = "empty"
			p.Spec.ResourceSelectors[0].Name = ""
			a.reviewer.client = &fakeSubjectAccessReviewClient{create: func(_ context.Context, review *authorizationv1.SubjectAccessReview) error {
				review.Status.Denied = review.Spec.ResourceAttributes.Verb == listVerb
				review.Status.Allowed = !review.Status.Denied
				return nil
			}}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mapper := placementTestMapper()
			scheme := runtime.NewScheme()
			if err := corev1.AddToScheme(scheme); err != nil {
				t.Fatal(err)
			}
			reader := fake.NewClientBuilder().WithScheme(scheme).WithObjects(&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: firstConfigMapName, Namespace: testNamespace}}).Build()
			reviewer, err := NewReviewer(&fakeSubjectAccessReviewClient{create: func(_ context.Context, r *authorizationv1.SubjectAccessReview) error {
				r.Status.Allowed = true
				return nil
			}}, mapper, 1)
			if err != nil {
				t.Fatal(err)
			}
			a, err := NewPlacementAuthorizer(reader, mapper, reviewer, &testinformer.FakeManager{}, resourceeligibility.AllowAll(mapper))
			if err != nil {
				t.Fatal(err)
			}
			p := &placementv1beta1.ResourcePlacement{
				ObjectMeta: metav1.ObjectMeta{Name: testPlacementName, Namespace: testNamespace},
				Spec:       placementv1beta1.PlacementSpec{ResourceSelectors: []placementv1beta1.ResourceSelectorTerm{{Version: "v1", Kind: utils.ConfigMapKind, Name: firstConfigMapName}}},
			}
			tt.modify(a, p)
			result := a.Authorize(context.Background(), authenticationv1.UserInfo{Username: testRequester}, p)
			wantDecision := DecisionIndeterminate
			if tt.denied {
				wantDecision = DecisionDenied
			}
			if result.Decision != wantDecision || (tt.denied && result.DenialReason == "") || (!tt.denied && result.Err == nil) {
				t.Errorf("Authorize() = %+v, want failure (denied=%v)", result, tt.denied)
			}
		})
	}
}

func TestPlacementAuthorizeNamespaceExpansionFailures(t *testing.T) {
	tests := []struct {
		name   string
		modify func(*PlacementAuthorizer, *placementv1beta1.ClusterResourcePlacement)
	}{
		{name: "missing resource informer", modify: func(a *PlacementAuthorizer, _ *placementv1beta1.ClusterResourcePlacement) { a.resourceInformer = nil }},
		{name: "unresolved inventory resource", modify: func(a *PlacementAuthorizer, _ *placementv1beta1.ClusterResourcePlacement) {
			a.resourceInformer = &testinformer.FakeManager{NamespaceScopedResources: []schema.GroupVersionResource{corev1.SchemeGroupVersion.WithResource("unknown")}}
		}},
		{name: "namespace get API failure", modify: func(a *PlacementAuthorizer, _ *placementv1beta1.ClusterResourcePlacement) {
			a.reader = fake.NewClientBuilder().WithInterceptorFuncs(interceptor.Funcs{
				Get: func(context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption) error {
					return errors.New("namespace get unavailable")
				},
			}).Build()
		}},
		{name: "namespace list API failure", modify: func(a *PlacementAuthorizer, p *placementv1beta1.ClusterResourcePlacement) {
			p.Spec.ResourceSelectors[0].Name = ""
			reader := fake.NewClientBuilder().WithObjects(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: testNamespace}}).WithInterceptorFuncs(interceptor.Funcs{
				List: func(context.Context, client.WithWatch, client.ObjectList, ...client.ListOption) error {
					return errors.New("namespace expansion list unavailable")
				},
			}).Build()
			a.reader = reader
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mapper := placementTestMapper()
			reader := fake.NewClientBuilder().WithObjects(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: testNamespace}}).Build()
			reviewer, err := NewReviewer(&fakeSubjectAccessReviewClient{create: func(_ context.Context, review *authorizationv1.SubjectAccessReview) error {
				review.Status.Allowed = true
				return nil
			}}, mapper, 1)
			if err != nil {
				t.Fatal(err)
			}
			inventory := &testinformer.FakeManager{NamespaceScopedResources: []schema.GroupVersionResource{corev1.SchemeGroupVersion.WithResource("configmaps")}}
			a, err := NewPlacementAuthorizer(reader, mapper, reviewer, inventory, resourceeligibility.AllowAll(mapper))
			if err != nil {
				t.Fatal(err)
			}
			p := &placementv1beta1.ClusterResourcePlacement{Spec: placementv1beta1.PlacementSpec{ResourceSelectors: []placementv1beta1.ResourceSelectorTerm{{Version: "v1", Kind: utils.NamespaceGVK.Kind, Name: testNamespace}}}}
			tt.modify(a, p)
			if result := a.Authorize(context.Background(), authenticationv1.UserInfo{Username: testRequester}, p); result.Decision != DecisionIndeterminate || result.Err == nil {
				t.Errorf("Authorize() = %+v, want namespace expansion error", result)
			}
		})
	}
}

func TestPlacementAuthorizeSkipsIneligibleKinds(t *testing.T) {
	mapper := placementTestMapper()
	checker := resourceeligibility.AllowAll(mapper)
	if err := checker.SetGVKCheckList(resourceeligibility.GVKEligibilityModeDenyList, []schema.GroupVersionKind{corev1.SchemeGroupVersion.WithKind(utils.ConfigMapKind)}); err != nil {
		t.Fatal(err)
	}
	reviewer, err := NewReviewer(&fakeSubjectAccessReviewClient{create: func(context.Context, *authorizationv1.SubjectAccessReview) error {
		t.Error("Authorize() submitted a SubjectAccessReview for an ineligible kind")
		return errors.New("unexpected SubjectAccessReview")
	}}, mapper, 1)
	if err != nil {
		t.Fatal(err)
	}
	a, err := NewPlacementAuthorizer(fake.NewClientBuilder().Build(), mapper, reviewer, &testinformer.FakeManager{}, checker)
	if err != nil {
		t.Fatal(err)
	}
	p := &placementv1beta1.ResourcePlacement{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace},
		Spec: placementv1beta1.PlacementSpec{ResourceSelectors: []placementv1beta1.ResourceSelectorTerm{{
			Version: "v1", Kind: utils.ConfigMapKind, Name: firstConfigMapName,
		}}},
	}
	result := a.Authorize(context.Background(), authenticationv1.UserInfo{Username: testRequester}, p)
	if diff := cmp.Diff(Result{Decision: DecisionAllowed}, result); diff != "" {
		t.Errorf("Authorize() mismatch (-want +got):\n%s", diff)
	}
}

func TestPlacementAuthorizeUsesFreshReads(t *testing.T) {
	mapper := placementTestMapper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	reader := fake.NewClientBuilder().WithScheme(scheme).Build()
	var got []string
	reviewer, err := NewReviewer(&fakeSubjectAccessReviewClient{create: func(_ context.Context, review *authorizationv1.SubjectAccessReview) error {
		attributes := review.Spec.ResourceAttributes
		got = append(got, review.Spec.User+":"+attributes.Verb+":"+attributes.Resource+":"+attributes.Namespace)
		review.Status.Allowed = true
		return nil
	}}, mapper, 1)
	if err != nil {
		t.Fatal(err)
	}
	inventory := &testinformer.FakeManager{NamespaceScopedResources: []schema.GroupVersionResource{corev1.SchemeGroupVersion.WithResource("configmaps")}}
	a, err := NewPlacementAuthorizer(reader, mapper, reviewer, inventory, resourceeligibility.AllowAll(mapper))
	if err != nil {
		t.Fatal(err)
	}
	p := &placementv1beta1.ClusterResourcePlacement{
		Spec: placementv1beta1.PlacementSpec{ResourceSelectors: []placementv1beta1.ResourceSelectorTerm{{Version: "v1", Kind: utils.NamespaceGVK.Kind, SelectionScope: placementv1beta1.NamespaceWithResources}}},
	}
	if result := a.Authorize(context.Background(), authenticationv1.UserInfo{Username: "creator"}, p); result.Decision != DecisionAllowed {
		t.Fatal(result)
	}
	if err := reader.Create(context.Background(), &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: testNamespace}}); err != nil {
		t.Fatal(err)
	}
	if result := a.Authorize(context.Background(), authenticationv1.UserInfo{Username: "updater"}, p); result.Decision != DecisionAllowed {
		t.Fatal(result)
	}
	want := []string{"creator:list:namespaces:", "updater:list:namespaces:", "updater:list:configmaps:" + testNamespace}
	if !slices.Equal(got, want) {
		t.Errorf("Authorize() reviews = %v, want %v", got, want)
	}
}
