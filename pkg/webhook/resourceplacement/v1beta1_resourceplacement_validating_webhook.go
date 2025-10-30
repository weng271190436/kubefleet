/*
Copyright 2025 The KubeFleet Authors.

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

// Package resourceplacement implements the webhook for v1beta1 ResourcePlacement.
package resourceplacement

import (
	"context"
	"fmt"
	"net/http"

	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	placementv1beta1 "github.com/kubefleet-dev/kubefleet/apis/placement/v1beta1"
	"github.com/kubefleet-dev/kubefleet/pkg/utils"
	"github.com/kubefleet-dev/kubefleet/pkg/utils/validator"
)

const (
	allowUpdateOldInvalidRPFmt   = "allow update on old invalid v1beta1 RP with DeletionTimestamp set"
	denyUpdateOldInvalidRPFmt    = "deny update on old invalid v1beta1 RP with DeletionTimestamp not set %s"
	denyCreateUpdateInvalidRPFmt = "deny create/update v1beta1 RP has invalid fields %s"
)

var (
	// ValidationPath is the webhook service path which admission requests are routed to for validating v1beta1 RP resources.
	ValidationPath = fmt.Sprintf(utils.ValidationPathFmt, placementv1beta1.GroupVersion.Group, placementv1beta1.GroupVersion.Version, "clusterresourceplacement")
)

type resourcePlacementValidator struct {
	decoder webhook.AdmissionDecoder
}

// Add registers the webhook for K8s bulit-in object types.
func Add(mgr manager.Manager) error {
	hookServer := mgr.GetWebhookServer()
	hookServer.Register(ValidationPath, &webhook.Admission{Handler: &resourcePlacementValidator{admission.NewDecoder(mgr.GetScheme())}})
	return nil
}

// Handle resourcePlacementValidator handles create, update RP requests.
func (v *resourcePlacementValidator) Handle(_ context.Context, req admission.Request) admission.Response {
	var rp placementv1beta1.ResourcePlacement
	if req.Operation == admissionv1.Create || req.Operation == admissionv1.Update {
		klog.V(2).InfoS("handling RP", "operation", req.Operation, "namespacedName", types.NamespacedName{Name: req.Name})
		if err := v.decoder.Decode(req, &rp); err != nil {
			klog.ErrorS(err, "failed to decode v1beta1 RP object for create/update operation", "userName", req.UserInfo.Username, "groups", req.UserInfo.Groups)
			return admission.Errored(http.StatusBadRequest, err)
		}
		if req.Operation == admissionv1.Update {
			var oldRP placementv1beta1.ResourcePlacement
			if err := v.decoder.DecodeRaw(req.OldObject, &oldRP); err != nil {
				return admission.Errored(http.StatusBadRequest, err)
			}
			// this is a special case where we allow updates to old v1beta1 RP with invalid fields so that we can
			// update the RP to remove finalizer then delete RP.
			if err := validator.ValidateResourcePlacement(&oldRP); err != nil {
				if rp.DeletionTimestamp != nil {
					return admission.Allowed(allowUpdateOldInvalidRPFmt)
				}
				return admission.Denied(fmt.Sprintf(denyUpdateOldInvalidRPFmt, err))
			}
			// handle update case where placement type should be immutable.
			if validator.IsPlacementPolicyTypeUpdated(oldRP.Spec.Policy, rp.Spec.Policy) {
				return admission.Denied("placement type is immutable")
			}
			// handle update case where existing tolerations were updated/deleted
			if validator.IsTolerationsUpdatedOrDeleted(oldRP.Spec.Tolerations(), rp.Spec.Tolerations()) {
				return admission.Denied("tolerations have been updated/deleted, only additions to tolerations are allowed")
			}
		}
		if err := validator.ValidateResourcePlacement(&rp); err != nil {
			klog.V(2).InfoS("v1beta1 cluster resource placement has invalid fields, request is denied", "operation", req.Operation, "namespacedName", types.NamespacedName{Name: rp.Name})
			return admission.Denied(fmt.Sprintf(denyCreateUpdateInvalidRPFmt, err))
		}
	}
	klog.V(2).InfoS("user is allowed to modify v1beta1 cluster resource placement", "operation", req.Operation, "user", req.UserInfo.Username, "group", req.UserInfo.Groups, "namespacedName", types.NamespacedName{Name: rp.Name})
	return admission.Allowed("any user is allowed to modify v1beta1 RP")
}
