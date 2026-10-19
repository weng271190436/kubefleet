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

package clusterresourceplacement

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
	getNamespaceCheck   = "get namespaces /team"
	listNamespacesCheck = "list namespaces /"
	getVerb             = "get"
	configMapResource   = "configmaps"
)

func TestHandleSelectedResourceAuthorization(t *testing.T) {
	namespace := placementv1beta1.ResourceSelectorTerm{Version: "v1", Kind: "Namespace", Name: testNamespace, SelectionScope: placementv1beta1.NamespaceOnly}
	labeledNamespace := namespace
	labeledNamespace.Name = ""
	labeledNamespace.LabelSelector = &metav1.LabelSelector{MatchLabels: map[string]string{"selected": "yes"}}
	allNamespaces := namespace
	allNamespaces.Name = ""
	withResources := namespace
	withResources.SelectionScope = placementv1beta1.NamespaceWithResources
	withSelectors := namespace
	withSelectors.SelectionScope = placementv1beta1.NamespaceWithResourceSelectors
	configmaps := placementv1beta1.ResourceSelectorTerm{Version: "v1", Kind: "ConfigMap"}
	namedConfigMap := configmaps
	namedConfigMap.Name = "config"
	tests := []struct {
		name          string
		selectors     []placementv1beta1.ResourceSelectorTerm
		update        bool
		cleanup       bool
		deleting      bool
		changeSpec    bool
		modify        func(*placementv1beta1.ClusterResourcePlacement)
		denyVerb      string
		denyResource  string
		apiError      bool
		missingSource bool
		invalid       bool
		wantCode      int32
		wantChecks    []string
	}{
		{name: "named namespace", selectors: []placementv1beta1.ResourceSelectorTerm{namespace}, wantChecks: []string{getNamespaceCheck}},
		{name: "labeled namespaces need list without get", selectors: []placementv1beta1.ResourceSelectorTerm{labeledNamespace}, denyVerb: getVerb, wantChecks: []string{listNamespacesCheck}},
		{name: "all namespaces need list without get", selectors: []placementv1beta1.ResourceSelectorTerm{allNamespaces}, denyVerb: getVerb, wantChecks: []string{listNamespacesCheck}},
		{name: "namespace expansion needs list without content get", selectors: []placementv1beta1.ResourceSelectorTerm{withResources}, denyVerb: getVerb, denyResource: configMapResource, wantChecks: []string{getNamespaceCheck, "list configmaps team/"}},
		{name: "selective enumeration needs list without object get", selectors: []placementv1beta1.ResourceSelectorTerm{withSelectors, configmaps}, denyVerb: getVerb, denyResource: configMapResource, wantChecks: []string{getNamespaceCheck, "list configmaps team/"}},
		{name: "selective named resource requires get", selectors: []placementv1beta1.ResourceSelectorTerm{withSelectors, namedConfigMap}, wantChecks: []string{getNamespaceCheck, "get configmaps team/config"}},
		{name: "selective named resource denied", selectors: []placementv1beta1.ResourceSelectorTerm{withSelectors, namedConfigMap}, denyVerb: getVerb, denyResource: configMapResource, wantCode: http.StatusForbidden},
		{name: "namespace expansion list denied", selectors: []placementv1beta1.ResourceSelectorTerm{withResources}, denyVerb: "list", denyResource: configMapResource, wantCode: http.StatusForbidden},
		{name: "overlapping namespace selectors", selectors: []placementv1beta1.ResourceSelectorTerm{namespace, labeledNamespace}, wantChecks: []string{getNamespaceCheck, listNamespacesCheck}},
		{name: "unchanged spec skips authorization", selectors: []placementv1beta1.ResourceSelectorTerm{namespace}, update: true, missingSource: true},
		{name: "spec update reauthorizes unchanged selectors", selectors: []placementv1beta1.ResourceSelectorTerm{namespace}, update: true, changeSpec: true, wantChecks: []string{getNamespaceCheck}},
		{name: "label update skips authorization", selectors: []placementv1beta1.ResourceSelectorTerm{namespace}, update: true, missingSource: true, modify: func(p *placementv1beta1.ClusterResourcePlacement) { p.Labels = map[string]string{"updated": "true"} }},
		{name: "annotation update skips authorization", selectors: []placementv1beta1.ResourceSelectorTerm{namespace}, update: true, missingSource: true, modify: func(p *placementv1beta1.ClusterResourcePlacement) {
			p.Annotations = map[string]string{"updated": "true"}
		}},
		{name: "active finalizer removal skips authorization", selectors: []placementv1beta1.ResourceSelectorTerm{namespace}, update: true, missingSource: true, modify: func(p *placementv1beta1.ClusterResourcePlacement) { p.Finalizers = nil }},
		{name: "active finalizer addition skips authorization", selectors: []placementv1beta1.ResourceSelectorTerm{namespace}, update: true, missingSource: true, modify: func(p *placementv1beta1.ClusterResourcePlacement) { p.Finalizers = append(p.Finalizers, "another") }},
		{name: "get denied", selectors: []placementv1beta1.ResourceSelectorTerm{namespace}, denyVerb: getVerb, wantCode: http.StatusForbidden},
		{name: "list denied", selectors: []placementv1beta1.ResourceSelectorTerm{labeledNamespace}, denyVerb: "list", wantCode: http.StatusForbidden},
		{name: "spec update denied", selectors: []placementv1beta1.ResourceSelectorTerm{namespace}, update: true, changeSpec: true, denyVerb: getVerb, wantCode: http.StatusForbidden},
		{name: "spec update SAR failure", selectors: []placementv1beta1.ResourceSelectorTerm{namespace}, update: true, changeSpec: true, apiError: true, wantCode: http.StatusInternalServerError},
		{name: "spec update live source failure", selectors: []placementv1beta1.ResourceSelectorTerm{namespace}, update: true, changeSpec: true, missingSource: true, wantCode: http.StatusInternalServerError},
		{name: "SAR failure", selectors: []placementv1beta1.ResourceSelectorTerm{namespace}, apiError: true, wantCode: http.StatusInternalServerError},
		{name: "live source failure", selectors: []placementv1beta1.ResourceSelectorTerm{namespace}, missingSource: true, wantCode: http.StatusInternalServerError},
		{name: "finalizer cleanup skips authorization", selectors: []placementv1beta1.ResourceSelectorTerm{namespace}, update: true, cleanup: true, missingSource: true},
		{name: "invalid placement cleanup skips authorization", selectors: []placementv1beta1.ResourceSelectorTerm{namespace}, update: true, cleanup: true, missingSource: true, invalid: true},
		{name: "invalid deleting placement retains existing allowance without finalizer removal", selectors: []placementv1beta1.ResourceSelectorTerm{namespace}, update: true, deleting: true, missingSource: true, invalid: true},
		{name: "invalid deleting placement retains existing allowance for spec changes", selectors: []placementv1beta1.ResourceSelectorTerm{namespace}, update: true, deleting: true, changeSpec: true, missingSource: true, invalid: true},
		{name: "invalid nondeleting placement remains denied", selectors: []placementv1beta1.ResourceSelectorTerm{namespace}, update: true, invalid: true, wantCode: http.StatusForbidden},
		{name: "valid deleting placement with unchanged spec skips authorization", selectors: []placementv1beta1.ResourceSelectorTerm{namespace}, update: true, deleting: true, missingSource: true},
		{name: "spec changes cannot use cleanup bypass", selectors: []placementv1beta1.ResourceSelectorTerm{namespace}, update: true, cleanup: true, changeSpec: true, denyVerb: getVerb, wantCode: http.StatusForbidden},
	}
	oldInformer, oldMapper := validator.ResourceInformer, validator.RestMapper
	t.Cleanup(func() { validator.ResourceInformer, validator.RestMapper = oldInformer, oldMapper })
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme := runtime.NewScheme()
			if err := corev1.AddToScheme(scheme); err != nil {
				t.Fatal(err)
			}
			if err := placementv1beta1.AddToScheme(scheme); err != nil {
				t.Fatal(err)
			}
			mapper := meta.NewDefaultRESTMapper([]schema.GroupVersion{corev1.SchemeGroupVersion})
			mapper.Add(utils.NamespaceGVK, meta.RESTScopeRoot)
			mapper.Add(corev1.SchemeGroupVersion.WithKind("ConfigMap"), meta.RESTScopeNamespace)
			inventory := &testinformer.FakeManager{
				APIResources:             map[schema.GroupVersionKind]bool{utils.NamespaceGVK: true},
				IsClusterScopedResource:  true,
				NamespaceScopedResources: []schema.GroupVersionResource{corev1.SchemeGroupVersion.WithResource("configmaps")},
			}
			validator.ResourceInformer, validator.RestMapper = inventory, mapper
			objects := []client.Object{&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "config", Namespace: testNamespace}}}
			if !tt.missingSource {
				objects = append(objects, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: testNamespace, Labels: map[string]string{"selected": "yes"}}})
			}
			reader := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
			user := authenticationv1.UserInfo{Username: "updating-user", UID: "uid", Groups: []string{"developers"}, Extra: map[string]authenticationv1.ExtraValue{"tenant": {testNamespace}}}
			var checks []string
			sarClient := fake.NewClientBuilder().WithInterceptorFuncs(interceptor.Funcs{Create: func(_ context.Context, _ client.WithWatch, obj client.Object, _ ...client.CreateOption) error {
				review, ok := obj.(*authorizationv1.SubjectAccessReview)
				if !ok {
					return fmt.Errorf("Create() object = %T, want SubjectAccessReview", obj)
				}
				if diff := cmp.Diff(user, authenticationv1.UserInfo{Username: review.Spec.User, UID: review.Spec.UID, Groups: review.Spec.Groups, Extra: map[string]authenticationv1.ExtraValue{"tenant": authenticationv1.ExtraValue(review.Spec.Extra["tenant"])}}); diff != "" {
					t.Errorf("Handle() user mismatch (-want +got):\n%s", diff)
				}
				attr := review.Spec.ResourceAttributes
				checks = append(checks, fmt.Sprintf("%s %s %s/%s", attr.Verb, attr.Resource, attr.Namespace, attr.Name))
				if tt.apiError {
					return errors.New("SAR unavailable")
				}
				review.Status.Denied = attr.Verb == tt.denyVerb && (tt.denyResource == "" || attr.Resource == tt.denyResource)
				review.Status.Allowed = !review.Status.Denied
				return nil
			}}).Build()
			reviewer, err := authorization.NewReviewer(sarClient, mapper, 1)
			if err != nil {
				t.Fatal(err)
			}
			authorizer, err := authorization.NewPlacementAuthorizer(reader, mapper, reviewer, inventory, resourceeligibility.AllowAll(mapper))
			if err != nil {
				t.Fatal(err)
			}
			handler := &clusterResourcePlacementValidator{
				decoder:    admission.NewDecoder(scheme),
				authorizer: authorizer,
			}
			old := &placementv1beta1.ClusterResourcePlacement{ObjectMeta: metav1.ObjectMeta{Name: "placement", Finalizers: []string{"cleanup"}}, Spec: placementv1beta1.PlacementSpec{ResourceSelectors: tt.selectors}}
			if tt.invalid {
				old.Spec.RevisionHistoryLimit = ptr.To(int32(-1))
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
			response := handler.Handle(context.Background(), admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{Operation: op, UserInfo: user, Object: runtime.RawExtension{Raw: currentRaw}, OldObject: runtime.RawExtension{Raw: oldRaw}}})
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
