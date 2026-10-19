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

	authenticationv1 "k8s.io/api/authentication/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	placementv1beta1 "github.com/kubefleet-dev/kubefleet/apis/placement/v1beta1"
	"github.com/kubefleet-dev/kubefleet/pkg/utils"
	"github.com/kubefleet-dev/kubefleet/pkg/utils/informer"
	"github.com/kubefleet-dev/kubefleet/pkg/utils/resourceeligibility"
)

// PlacementAuthorizer reviews source-resource access for placement selectors.
type PlacementAuthorizer struct {
	reader                     client.Reader
	restMapper                 meta.RESTMapper
	reviewer                   *Reviewer
	resourceInformer           informer.Manager
	resourceEligibilityChecker resourceeligibility.Checker
}

// NewPlacementAuthorizer creates a placement authorizer with all dependencies required for selector resolution.
// reader must be uncached (for example, manager.GetAPIReader()) for Namespace selection.
// resourceInformer supplies resource types for namespace expansion, not cached objects.
func NewPlacementAuthorizer(reader client.Reader, restMapper meta.RESTMapper, reviewer *Reviewer, resourceInformer informer.Manager, checker resourceeligibility.Checker) (*PlacementAuthorizer, error) {
	if reader == nil {
		return nil, errors.New("resource reader must not be nil")
	}
	if restMapper == nil {
		return nil, errors.New("REST mapper must not be nil")
	}
	if reviewer == nil {
		return nil, errors.New("authorization reviewer must not be nil")
	}
	if resourceInformer == nil {
		return nil, errors.New("resource informer must not be nil")
	}
	if checker == nil {
		return nil, errors.New("resource eligibility checker must not be nil")
	}
	return &PlacementAuthorizer{
		reader:                     reader,
		restMapper:                 restMapper,
		reviewer:                   reviewer,
		resourceInformer:           resourceInformer,
		resourceEligibilityChecker: checker,
	}, nil
}

// Authorize requires get access for named selections and list access for enumerated scopes.
func (a *PlacementAuthorizer) Authorize(ctx context.Context, user authenticationv1.UserInfo, placement placementv1beta1.PlacementObj) Result {
	if a == nil || a.reader == nil || a.restMapper == nil || a.reviewer == nil || a.resourceInformer == nil || a.resourceEligibilityChecker == nil {
		return Result{Decision: DecisionIndeterminate, Err: fmt.Errorf("placement authorization dependencies are incomplete")}
	}
	attributes, err := a.resolve(ctx, placement)
	if err != nil {
		return Result{Decision: DecisionIndeterminate, Err: err}
	}
	return a.reviewer.Authorize(ctx, user, attributes...)
}

func (a *PlacementAuthorizer) resolve(ctx context.Context, placement placementv1beta1.PlacementObj) ([]authorizationv1.ResourceAttributes, error) {
	switch placement := placement.(type) {
	case *placementv1beta1.ResourcePlacement:
		if placement == nil {
			return nil, fmt.Errorf("resource placement must not be nil")
		}
		if placement.Namespace == "" {
			return nil, fmt.Errorf("resource placement must specify a namespace")
		}
		return a.resolveResourcePlacement(placement)
	case *placementv1beta1.ClusterResourcePlacement:
		if placement == nil {
			return nil, fmt.Errorf("cluster resource placement must not be nil")
		}
		if placement.Namespace != "" {
			return nil, fmt.Errorf("cluster resource placement must not specify a namespace")
		}
		return a.resolveClusterResourcePlacement(ctx, placement)
	default:
		return nil, fmt.Errorf("unsupported placement type %T", placement)
	}
}

func (a *PlacementAuthorizer) resolveResourcePlacement(placement *placementv1beta1.ResourcePlacement) ([]authorizationv1.ResourceAttributes, error) {
	var attributes []authorizationv1.ResourceAttributes
	for _, selector := range placement.Spec.ResourceSelectors {
		gvk := selectorGVK(selector)
		mapping, err := a.restMapper.RESTMapping(gvk.GroupKind(), gvk.Version)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve selector %s: %w", gvk, err)
		}
		if mapping.Scope.Name() != meta.RESTScopeNameNamespace {
			return nil, fmt.Errorf("resource placement cannot select cluster-scoped resource %s", gvk)
		}
		if !a.resourceEligibilityChecker.AllowsGVK(gvk) {
			continue
		}
		check, err := a.selectorAttributes(mapping.Resource, placement.Namespace, selector)
		if err != nil {
			return nil, err
		}
		attributes = append(attributes, check)
	}
	return attributes, nil
}

func (a *PlacementAuthorizer) resolveClusterResourcePlacement(ctx context.Context, placement *placementv1beta1.ClusterResourcePlacement) ([]authorizationv1.ResourceAttributes, error) {
	selectors := placement.Spec.ResourceSelectors
	var attributes []authorizationv1.ResourceAttributes
	selectedNamespace := ""
	for _, selector := range selectors {
		if selectorGVK(selector) != utils.NamespaceGVK {
			continue
		}
		if selector.SelectionScope == placementv1beta1.NamespaceWithResourceSelectors {
			if selectedNamespace != "" {
				return nil, fmt.Errorf("NamespaceWithResourceSelectors requires one named namespace in a cluster-scoped placement")
			}
			selectedNamespace = selector.Name
		}
		checks, err := a.resolveNamespaceSelector(ctx, selector)
		if err != nil {
			return nil, err
		}
		attributes = append(attributes, checks...)
	}

	for _, selector := range selectors {
		gvk := selectorGVK(selector)
		if gvk == utils.NamespaceGVK {
			continue
		}
		mapping, err := a.restMapper.RESTMapping(gvk.GroupKind(), gvk.Version)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve selector %s: %w", gvk, err)
		}
		namespace := ""
		if mapping.Scope.Name() == meta.RESTScopeNameNamespace {
			namespace = selectedNamespace
			if namespace == "" {
				return nil, fmt.Errorf("cluster resource placement requires NamespaceWithResourceSelectors to select namespaced resource %s", gvk)
			}
		}
		if !a.resourceEligibilityChecker.AllowsGVK(gvk) {
			continue
		}
		check, err := a.selectorAttributes(mapping.Resource, namespace, selector)
		if err != nil {
			return nil, err
		}
		attributes = append(attributes, check)
	}
	return attributes, nil
}

func (a *PlacementAuthorizer) resolveNamespaceSelector(ctx context.Context, selector placementv1beta1.ResourceSelectorTerm) ([]authorizationv1.ResourceAttributes, error) {
	if selector.SelectionScope == placementv1beta1.NamespaceWithResourceSelectors && (selector.Name == "" || selector.LabelSelector != nil) {
		return nil, fmt.Errorf("NamespaceWithResourceSelectors requires one named namespace in a cluster-scoped placement")
	}
	mapping, err := a.restMapper.RESTMapping(utils.NamespaceGVK.GroupKind(), utils.NamespaceGVK.Version)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve selector %s: %w", utils.NamespaceGVK, err)
	}
	if !a.resourceEligibilityChecker.AllowsGVK(utils.NamespaceGVK) {
		return nil, nil
	}
	check, err := a.selectorAttributes(mapping.Resource, "", selector)
	if err != nil {
		return nil, err
	}
	objects, err := a.selectNamespaces(ctx, selector)
	if err != nil {
		return nil, err
	}
	attributes := []authorizationv1.ResourceAttributes{check}
	for _, obj := range objects {
		if !a.resourceEligibilityChecker.AllowsNamespace(obj.GetName()) {
			return nil, fmt.Errorf("namespace %q is not eligible for placement", obj.GetName())
		}
	}
	switch selector.SelectionScope {
	case placementv1beta1.NamespaceOnly:
		return attributes, nil
	case "", placementv1beta1.NamespaceWithResources:
		for _, obj := range objects {
			checks, err := a.expandNamespace(obj.GetName())
			if err != nil {
				return nil, err
			}
			attributes = append(attributes, checks...)
		}
		return attributes, nil
	case placementv1beta1.NamespaceWithResourceSelectors:
		if len(objects) != 1 {
			return nil, fmt.Errorf("NamespaceWithResourceSelectors requires exactly one eligible namespace")
		}
		return attributes, nil
	default:
		return nil, fmt.Errorf("unsupported namespace selection scope %q", selector.SelectionScope)
	}
}

func selectorGVK(selector placementv1beta1.ResourceSelectorTerm) schema.GroupVersionKind {
	return schema.GroupVersionKind{Group: selector.Group, Version: selector.Version, Kind: selector.Kind}
}

func (a *PlacementAuthorizer) selectorAttributes(gvr schema.GroupVersionResource, namespace string, selector placementv1beta1.ResourceSelectorTerm) (authorizationv1.ResourceAttributes, error) {
	if namespace != "" && !a.resourceEligibilityChecker.AllowsNamespace(namespace) {
		return authorizationv1.ResourceAttributes{}, fmt.Errorf("namespace %q is not eligible for placement", namespace)
	}
	if selector.Name != "" {
		if selector.LabelSelector != nil {
			return authorizationv1.ResourceAttributes{}, fmt.Errorf("name and labelSelector are mutually exclusive")
		}
		return resourceAttributes(gvr, "get", namespace, selector.Name), nil
	}
	if selector.LabelSelector != nil {
		if _, err := metav1.LabelSelectorAsSelector(selector.LabelSelector); err != nil {
			return authorizationv1.ResourceAttributes{}, fmt.Errorf("invalid resource label selector: %w", err)
		}
	}
	return resourceAttributes(gvr, "list", namespace, ""), nil
}

func (a *PlacementAuthorizer) selectNamespaces(ctx context.Context, selector placementv1beta1.ResourceSelectorTerm) ([]corev1.Namespace, error) {
	var objects []corev1.Namespace
	if selector.Name != "" {
		var obj corev1.Namespace
		if err := a.reader.Get(ctx, types.NamespacedName{Name: selector.Name}, &obj); err != nil {
			return nil, fmt.Errorf("failed to get selected namespace %q: %w", selector.Name, err)
		}
		objects = append(objects, obj)
	} else {
		labelSelector := labels.Everything()
		if selector.LabelSelector != nil {
			var err error
			labelSelector, err = metav1.LabelSelectorAsSelector(selector.LabelSelector)
			if err != nil {
				return nil, fmt.Errorf("invalid namespace label selector: %w", err)
			}
		}
		var list corev1.NamespaceList
		if err := a.reader.List(ctx, &list, client.MatchingLabelsSelector{Selector: labelSelector}); err != nil {
			return nil, fmt.Errorf("failed to list selected namespaces: %w", err)
		}
		objects = list.Items
	}
	selected := make([]corev1.Namespace, 0, len(objects))
	for i := range objects {
		obj := &objects[i]
		if obj.GetDeletionTimestamp() != nil {
			continue
		}
		selected = append(selected, *obj)
	}
	return selected, nil
}

func (a *PlacementAuthorizer) expandNamespace(namespace string) ([]authorizationv1.ResourceAttributes, error) {
	var attributes []authorizationv1.ResourceAttributes
	for _, gvr := range a.resourceInformer.GetNameSpaceScopedResources() {
		eligible, err := a.resourceEligibilityChecker.AllowsGVR(gvr)
		if err != nil {
			return nil, fmt.Errorf("failed to determine eligibility for %s: %w", gvr, err)
		}
		if !eligible {
			continue
		}
		attributes = append(attributes, resourceAttributes(gvr, "list", namespace, ""))
	}
	return attributes, nil
}

func resourceAttributes(gvr schema.GroupVersionResource, verb, namespace, name string) authorizationv1.ResourceAttributes {
	return authorizationv1.ResourceAttributes{
		Group: gvr.Group, Version: gvr.Version, Resource: gvr.Resource,
		Verb: verb, Namespace: namespace, Name: name,
	}
}
