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

package resourceplacement

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	placementv1beta1 "github.com/kubefleet-dev/kubefleet/apis/placement/v1beta1"
	"github.com/kubefleet-dev/kubefleet/pkg/utils"
	"github.com/kubefleet-dev/kubefleet/pkg/utils/authorization"
	"github.com/kubefleet-dev/kubefleet/pkg/utils/resourceeligibility"
	"github.com/kubefleet-dev/kubefleet/pkg/utils/validator"
	testinformer "github.com/kubefleet-dev/kubefleet/test/utils/informer"
)

const (
	testNamespace       = "team"
	getConfigMapCheck   = "get configmaps team/config"
	listConfigMapsCheck = "list configmaps team/"
	getVerb             = "get"
)

func TestHandleSelectedResourceAuthorization(t *testing.T) {
	named := placementv1beta1.ResourceSelectorTerm{Version: "v1", Kind: utils.ConfigMapKind, Name: "config"}
	all := placementv1beta1.ResourceSelectorTerm{Version: "v1", Kind: utils.ConfigMapKind}
	labeled := placementv1beta1.ResourceSelectorTerm{
		Version: "v1", Kind: utils.ConfigMapKind,
		LabelSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"selected": "yes"}},
	}
	tests := []struct {
		name       string
		selectors  []placementv1beta1.ResourceSelectorTerm
		update     bool
		cleanup    bool
		deleting   bool
		changeSpec bool
		modify     func(*placementv1beta1.ResourcePlacement)
		denyVerb   string
		apiError   bool
		invalid    bool
		wantCode   int32
		wantChecks []string
	}{
		{name: "named", selectors: []placementv1beta1.ResourceSelectorTerm{named}, wantChecks: []string{getConfigMapCheck}},
		{name: "label needs list without get", selectors: []placementv1beta1.ResourceSelectorTerm{labeled}, denyVerb: getVerb, wantChecks: []string{listConfigMapsCheck}},
		{name: "all of kind needs list without get", selectors: []placementv1beta1.ResourceSelectorTerm{all}, denyVerb: getVerb, wantChecks: []string{listConfigMapsCheck}},
		{name: "overlapping selectors", selectors: []placementv1beta1.ResourceSelectorTerm{named, all, labeled}, wantChecks: []string{listConfigMapsCheck, getConfigMapCheck}},
		{name: "unchanged spec skips authorization", selectors: []placementv1beta1.ResourceSelectorTerm{named}, update: true},
		{name: "spec update reauthorizes unchanged selectors", selectors: []placementv1beta1.ResourceSelectorTerm{named}, update: true, changeSpec: true, wantChecks: []string{getConfigMapCheck}},
		{name: "label update skips authorization", selectors: []placementv1beta1.ResourceSelectorTerm{named}, update: true, modify: func(p *placementv1beta1.ResourcePlacement) { p.Labels = map[string]string{"updated": "true"} }},
		{name: "annotation update skips authorization", selectors: []placementv1beta1.ResourceSelectorTerm{named}, update: true, modify: func(p *placementv1beta1.ResourcePlacement) { p.Annotations = map[string]string{"updated": "true"} }},
		{name: "active finalizer removal skips authorization", selectors: []placementv1beta1.ResourceSelectorTerm{named}, update: true, modify: func(p *placementv1beta1.ResourcePlacement) { p.Finalizers = nil }},
		{name: "active finalizer addition skips authorization", selectors: []placementv1beta1.ResourceSelectorTerm{named}, update: true, modify: func(p *placementv1beta1.ResourcePlacement) { p.Finalizers = append(p.Finalizers, "another") }},
		{name: "get denied", selectors: []placementv1beta1.ResourceSelectorTerm{named}, denyVerb: getVerb, wantCode: http.StatusForbidden},
		{name: "list denied", selectors: []placementv1beta1.ResourceSelectorTerm{all}, denyVerb: "list", wantCode: http.StatusForbidden},
		{name: "spec update denied", selectors: []placementv1beta1.ResourceSelectorTerm{named}, update: true, changeSpec: true, denyVerb: getVerb, wantCode: http.StatusForbidden},
		{name: "spec update SAR failure", selectors: []placementv1beta1.ResourceSelectorTerm{named}, update: true, changeSpec: true, apiError: true, wantCode: http.StatusInternalServerError},
		{name: "SAR failure", selectors: []placementv1beta1.ResourceSelectorTerm{named}, apiError: true, wantCode: http.StatusInternalServerError},
		{name: "finalizer cleanup skips authorization", selectors: []placementv1beta1.ResourceSelectorTerm{named}, update: true, cleanup: true},
		{name: "invalid placement cleanup skips authorization", selectors: []placementv1beta1.ResourceSelectorTerm{named}, update: true, cleanup: true, invalid: true},
		{name: "invalid deleting placement retains existing allowance without finalizer removal", selectors: []placementv1beta1.ResourceSelectorTerm{named}, update: true, deleting: true, invalid: true},
		{name: "invalid deleting placement retains existing allowance for spec changes", selectors: []placementv1beta1.ResourceSelectorTerm{named}, update: true, deleting: true, changeSpec: true, invalid: true},
		{name: "invalid nondeleting placement remains denied", selectors: []placementv1beta1.ResourceSelectorTerm{named}, update: true, invalid: true, wantCode: http.StatusForbidden},
		{name: "valid deleting placement with unchanged spec skips authorization", selectors: []placementv1beta1.ResourceSelectorTerm{named}, update: true, deleting: true},
		{name: "spec changes cannot use cleanup bypass", selectors: []placementv1beta1.ResourceSelectorTerm{named}, update: true, cleanup: true, changeSpec: true, denyVerb: getVerb, wantCode: http.StatusForbidden},
	}
	oldInformer, oldMapper := validator.ResourceInformer, validator.RestMapper
	t.Cleanup(func() { validator.ResourceInformer, validator.RestMapper = oldInformer, oldMapper })
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme := runtime.NewScheme()
			if err := placementv1beta1.AddToScheme(scheme); err != nil {
				t.Fatal(err)
			}
			mapper := meta.NewDefaultRESTMapper([]schema.GroupVersion{corev1.SchemeGroupVersion})
			mapper.Add(corev1.SchemeGroupVersion.WithKind("ConfigMap"), meta.RESTScopeNamespace)
			validator.RestMapper = mapper
			validator.ResourceInformer = &testinformer.FakeManager{APIResources: map[schema.GroupVersionKind]bool{corev1.SchemeGroupVersion.WithKind("ConfigMap"): false}, IsClusterScopedResource: true}
			user := authenticationv1.UserInfo{Username: "updating-user", UID: "uid", Groups: []string{"developers"}, Extra: map[string]authenticationv1.ExtraValue{"tenant": {testNamespace}}}
			var checks []string
			sarClient := fake.NewClientBuilder().WithInterceptorFuncs(interceptor.Funcs{Create: func(_ context.Context, _ client.WithWatch, obj client.Object, _ ...client.CreateOption) error {
				review, ok := obj.(*authorizationv1.SubjectAccessReview)
				if !ok {
					return fmt.Errorf("Create() object = %T, want SubjectAccessReview", obj)
				}
				wantSpec := authorizationv1.SubjectAccessReviewSpec{
					User: user.Username, UID: user.UID, Groups: user.Groups,
					Extra:              map[string]authorizationv1.ExtraValue{"tenant": {testNamespace}},
					ResourceAttributes: review.Spec.ResourceAttributes,
				}
				if diff := cmp.Diff(wantSpec, review.Spec); diff != "" {
					t.Errorf("Handle() SubjectAccessReview mismatch (-want +got):\n%s", diff)
				}
				attr := review.Spec.ResourceAttributes
				checks = append(checks, fmt.Sprintf("%s %s %s/%s", attr.Verb, attr.Resource, attr.Namespace, attr.Name))
				if tt.apiError {
					return errors.New("SAR unavailable")
				}
				review.Status.Denied = attr.Verb == tt.denyVerb
				review.Status.Allowed = !review.Status.Denied
				return nil
			}}).Build()
			reviewer, err := authorization.NewReviewer(sarClient, mapper, 1)
			if err != nil {
				t.Fatal(err)
			}
			authorizer, err := authorization.NewResourcePlacementAuthorizer(mapper, reviewer, resourceeligibility.AllowAll(mapper))
			if err != nil {
				t.Fatal(err)
			}
			handler := &resourcePlacementValidator{
				decoder:    admission.NewDecoder(scheme),
				authorizer: authorizer,
			}
			old := &placementv1beta1.ResourcePlacement{ObjectMeta: metav1.ObjectMeta{Name: "placement", Namespace: testNamespace, Finalizers: []string{"cleanup"}}, Spec: placementv1beta1.PlacementSpec{ResourceSelectors: tt.selectors}}
			if tt.invalid {
				old.Spec.Strategy.Type = "invalid"
			}
			if tt.cleanup || tt.deleting {
				now := metav1.Now()
				old.DeletionTimestamp = &now
			}
			current := old.DeepCopy()
			if tt.cleanup {
				current.Finalizers = nil
			}
			if tt.changeSpec {
				current.Spec.RevisionHistoryLimit = ptr.To(int32(5))
			}
			if tt.modify != nil {
				tt.modify(current)
			}
			currentRaw, err := json.Marshal(current)
			if err != nil {
				t.Fatal(err)
			}
			oldRaw, err := json.Marshal(old)
			if err != nil {
				t.Fatal(err)
			}
			op := admissionv1.Create
			if tt.update {
				op = admissionv1.Update
			}
			response := handler.Handle(context.Background(), admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{Operation: op, Namespace: testNamespace, UserInfo: user, Object: runtime.RawExtension{Raw: currentRaw}, OldObject: runtime.RawExtension{Raw: oldRaw}}})
			if response.Allowed != (tt.wantCode == 0) {
				t.Fatalf("Handle() = %+v, want code %d", response, tt.wantCode)
			}
			if tt.wantCode != 0 && response.Result.Code != tt.wantCode {
				t.Errorf("Handle() code = %d, want %d", response.Result.Code, tt.wantCode)
			}
			if tt.wantCode == 0 {
				if diff := cmp.Diff(tt.wantChecks, checks, cmpopts.SortSlices(func(a, b string) bool { return a < b })); diff != "" {
					t.Errorf("Handle() checks mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}
