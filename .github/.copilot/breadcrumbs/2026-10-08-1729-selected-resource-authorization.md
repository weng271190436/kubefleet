# Enforce selected-resource authorization

**Date**: October 8, 2026 17:29 UTC
**Task**: Prevent placement and override APIs from using Fleet's controller permissions to access resources the requester could not access directly.

## Requirements

1. Enforce selected-resource authorization for ClusterResourcePlacement, ResourcePlacement, ClusterResourceOverride, and ResourceOverride create and update requests.
2. Build SubjectAccessReview requests from the admission request's complete user information: username, UID, groups, and extras.
3. Fail closed when resource resolution or authorization cannot be completed.
4. Require `get` for resources selected by name.
5. For CRP/RP label and all-of-kind selectors, require `list` in the relevant scope, without individual `get` checks for enumerated objects.
6. For namespace selection, authorize the Namespace selection using `get` by name or `list` for label/all-of-kind selection. For NamespaceWithResources, require `list` per eligible expanded namespaced resource type, without individual `get` checks for their objects.
7. Ignore resources that begin matching dynamic selectors after admission in this implementation.
8. Require `patch` for JSONPatch overrides and `delete` for Delete overrides.
9. Require Kubernetes RBAC privilege-protection checks when overrides affect Role, ClusterRole, RoleBinding, or ClusterRoleBinding resources.
10. For CRP/RP, authorize creates and reauthorize the complete selected set on spec-changing updates, even if selectors are unchanged. Overrides retain the original every-update reauthorization requirement.
11. For CRP/RP, skip selected-resource authorization on updates with semantically unchanged specs, including label, annotation, and finalizer changes regardless of deletion state. Preserve existing validation behavior. For overrides, retain the deletion/finalizer cleanup exception.
12. Enable enforcement by default and provide a temporary feature flag to disable it.

## Plan

### Phase 1: Authorization foundation and tests

- [x] Add a selected-resource reviewer that creates Kubernetes SubjectAccessReviews and preserves all admission user information.
- [x] Add RESTMapper-based conversion from selector GVKs to the plural GVRs required by SubjectAccessReview.
- [x] Deduplicate identical checks within one authorization batch and use bounded concurrency for object-level reviews.
- [x] Add unit tests for allowed, denied, no-opinion, API-error, timeout, identity-copying, and duplicate-review cases.
- **Success criterion:** Authorization behavior is independently testable and every unresolved or unsuccessful review fails closed.

### Phase 2: Placement authorization

- [x] Resolve selected Namespaces using live hub API reads. Build ordinary resource permission checks from selectors and mappings without fetching their objects.
- [x] Authorize CRP and RP name, label, all-of-kind, NamespaceOnly, NamespaceWithResourceSelectors, and NamespaceWithResources selection modes.
- [x] Require selector-level `list` permission where Fleet enumerates resources and object-level `get` permission for resources explicitly selected by name.
- [x] Preserve the existing deletion/finalizer cleanup escape hatch.
- [x] Add CRP and RP webhook tests covering scope, selector modes, overlapping selectors, update reauthorization, denied access, and API failures.
- **Success criterion:** A placement is admitted only when the requester can list each enumerated scope and get each source object explicitly selected by name.

### Phase 3: Override authorization

- [ ] Authorize every currently selected CRO and RO target.
- [ ] Require `patch` for JSONPatch rules, including `remove` operations on fields, and `delete` when a Delete rule removes the entire selected resource from a member cluster.
- [ ] Apply or inspect override patches sufficiently to perform correct `escalate` checks for Role/ClusterRole rule changes and `bind` checks against the resulting RoleBinding/ClusterRoleBinding role reference.
- [ ] Add CRO and RO webhook tests for patch, delete, escalate, bind, namespaced scope, update reauthorization, and fail-closed behavior.
- **Success criterion:** Overrides cannot mutate, suppress, escalate, or bind selected RBAC resources beyond the requester's direct authority.

### Phase 4: Wiring, RBAC, and rollout

- [ ] Add a default-enabled hub-agent feature flag that can temporarily disable selected-resource authorization.
- [ ] Pass the RESTMapper, uncached/live resource reader, and SAR client into all four validating webhooks.
- [ ] Grant the hub-agent service account `create` on `authorization.k8s.io/subjectaccessreviews`.
- [ ] Update directly related Helm values and user-facing flag documentation.
- **Success criterion:** Default installations enforce authorization, while operators have an explicit temporary rollback switch.

### Phase 5: Verification

- [ ] Run formatting and focused authorization, webhook, and option tests.
- [ ] Run the smallest relevant integration tests using real Kubernetes RBAC authorization.
- [ ] Run `make reviewable` before submission.
- [ ] Update this breadcrumb with implementation details, changed files, and validation results.
- **Success criterion:** Focused and repository-required checks pass with no authorization bypass or unrelated behavior regression.

## Decisions

1. Cover all four v1beta1 APIs in the first implementation: CRP, RP, CRO, and RO.
2. Dynamic resources that match after admission are an acknowledged limitation and are not blocked because dynamic selection is a core Fleet feature.
3. Placement label and all-of-kind selection requires `list` only. Named selection requires `get` for the named object.
4. NamespaceWithResources authorizes the Namespace selection and requires `list` for each relevant namespaced GVR, without individual `get` checks for enumerated objects.
5. Delete overrides require `delete`; JSONPatch overrides require `patch`.
6. CRP/RP creates and spec-changing updates authorize the complete selected set using the current requester's identity. Unchanged-spec updates skip selected-resource authorization but still undergo existing validation. Override updates retain every-update reauthorization.
7. Finalizer removal during deletion bypasses selected-resource authorization.
8. Enforcement is enabled by default behind a temporary disable flag.

## Non-goals

1. Continuous reauthorization when a new resource begins matching an existing dynamic selector.
2. Persisting creator identity for controller-time authorization.
3. Replacing Kubernetes RBAC or supporting label-restricted authorization policies beyond what SubjectAccessReview reports.

## Status

Plan approved by the user. Phases 1 and 2 are complete. Phase 2 was implemented on
`feat/selected-resource-authorization-phase-2`; Phases 3-5 have not started.

## Phase 2 implementation plan

- Resolve Namespace objects through an injected uncached reader; use selectors,
  REST mappings, and the controller's tracked namespaced resource inventory to
  build permission checks without reading ordinary source objects.
- Reuse the batch reviewer for selector-level list and explicitly named-object get checks.
- Add optional authorization dependencies to the CRP/RP handlers and shared validation
  path. Production registration, the default-enabled flag, and RBAC remain Phase 4.
- Authorize creates and spec-changing updates, and add focused resolver
  and webhook tests before running race tests and vet.

## Phase 2 implementation details

- Added `pkg/utils/authorization/placement.go` with a placement authorizer that
  separates permission construction from Namespace lookup. `selectorAttributes`
  derives get/list checks from selector metadata; `selectNamespaces` returns only
  typed Namespace objects using an injected uncached reader. Ordinary source
  objects are not fetched, so their existence and API availability are not
  admission preconditions. Namespace expansion builds list checks directly from
  the controller's tracked eligible namespaced GVRs without listing their objects.
- Added `NewPlacementAuthorizer` to validate the reader, REST mapper, reviewer,
  resource informer, and eligibility checker during initialization.
  Dependencies are private; tests initialize authorizers
  through the constructor. A nil or zero-value authorizer still fails closed.
  The informer supplies only the namespace-expansion resource inventory.
  The now-unused workload option was removed from the constructor.
- Applied RESTMapper-based scope checks, namespace eligibility, GVK eligibility,
  and deletion filtering for Namespace objects. After the user approved
  selector-derived permission checks, ordinary object propagation filtering and
  related Service lookups became unnecessary for authorization and were removed.
  `pkg/utils/controller/resource_selector_resolver.go` remains unchanged.
- Structured selector resolution with an explicit CRP/RP type switch and separate
  typed resolution paths. RP always resolves inside its own namespace; CRP handles
  Namespace selectors first in `resolveNamespaceSelector`, with one explicit switch
  over the three namespace modes, then resolves other resources at cluster scope or
  in the selective namespace. Tests cover mixed namespace/cluster-resource selections
  and selective namespace selectors appearing before or after the resources they scope.
  Namespace metadata no longer determines the placement type. Unsupported types,
  typed nils, and mismatched placement scope fail closed; tests cover all five
  primary selection cases and scope validation.
- Required `get` for named selections, plus `list` for every
  enumerated scope, including empty matches and eligible types expanded inside
  namespaces. Reused the Phase 1 reviewer's deduplication and bounded concurrency.
- On October 19, the user approved using `list` alone for label/all-of-kind
  selections and expanded resource collections, since Kubernetes list responses
  already contain the full objects. Removed per-object `get` checks for enumerated
  results. Named selectors, including a named Namespace, still require `get`.
  Tests verify that list-only access succeeds even when individual `get` would be
  denied, and that denied list or explicitly required get checks still reject.
- Added an optional authorizer to both placement handlers through
  `pkg/utils/validator/placement.go`. Creates and spec-changing updates use the
  current admission requester's identity, rebuild the complete permission
  checklist, and resolve selected Namespaces anew.
- Replaced the authorization result's implicit boolean/reason mapping with an
  explicit `Decision` (`Allowed`, `Denied`, or `Indeterminate`) and `DenialReason`.
  The reviewer preserves denial-over-error precedence; a denied result can carry
  additional diagnostic errors. The webhook switches on the decision, and unknown
  or malformed results fail closed. Added focused admission-mapping tests.
- Preserved the existing invalid-placement deletion exception unchanged: if the
  old placement is invalid and the new placement has a deletion timestamp, the
  handler still returns allowed without further validation or authorization.
  For updates reaching the new authorization gate, semantic spec equality skips
  only selected-resource authorization. Existing structural validation still runs.
  No deletion-timestamp or finalizer-specific checks are needed for that gate.
- Added CRP/RP regression tests for the existing invalid-placement exception,
  including updates without finalizer removal and updates with spec changes.
- On October 19, the user approved broadening the CRP/RP authorization exception
  from deleting-object finalizer cleanup to all unchanged-spec updates. Tests cover
  label, annotation, and active/deleting finalizer updates without live reads or
  SARs, plus reauthorization and failures on spec changes with unchanged selectors.
  This intentionally does not refresh authorization for unchanged-spec updates
  after dynamic selections or requester permissions change.
- Added resolver and real CRP/RP handler tests for selection modes, scope,
  overlapping selectors, fresh reads, user identity, denials, API failures,
  namespace expansion failures, eligibility, and cleanup. Selection tests reject
  any non-Namespace reader operation; RP webhook tests prove authorization still
  succeeds when ordinary source-object reads are unavailable.
- Production webhook registration intentionally does not inject the authorizer
  yet. Default-enabled enforcement, the rollback flag, dependencies, and SAR RBAC
  remain Phase 4; this phase alone does not enable enforcement in installations.

## Phase 2 validation

- Focused race tests passed for `pkg/utils/authorization`, `pkg/utils/validator`,
  `pkg/webhook/clusterresourceplacement`, and `pkg/webhook/resourceplacement`.
- Controller propagation regression tests passed with `-race` and
  `-run 'Test(GatherSelectedResource|FetchSelectedNamespace|ShouldPropagateObj)'`.
- `go vet` passed for all five affected packages.
- `go build ./cmd/hubagent/...` passed.
- Before committing, `make lint GOLANGCI_LINT=/home/weiweng/go/bin/golangci-lint`
  passed repository-wide with the installed repository-version linter (v2.13.2).
- Repository-configured lint passed with `--new-from-rev=HEAD`,
  `--max-issues-per-linter=0`, and `--max-same-issues=0` for the affected packages.
  Unfiltered package lint also reports pre-existing issues in untouched controller
  tests and the CRP mutating webhook tests; these were not changed.
- `git diff --check` passed. Go commands use
  `MS_GOTOOLCHAIN_ALLOW_NON_LOCAL=1 GOTOOLCHAIN=auto`, as in Phase 1.
- Full `make reviewable` and real Kubernetes RBAC integration remain Phase 5
  verification, before PR submission.

## Phase 1 implementation details

- Added `pkg/utils/authorization` with a reusable, stateless batch Reviewer.
- Preserved username, UID, groups, and deep-copied extras in every SubjectAccessReview.
- Added RESTMapper-based GVK-to-GVR conversion for correctly pluralized authorization attributes.
- Deduplicated identical attributes within each authorization batch; separate calls always perform fresh reviews.
- Limited concurrent SubjectAccessReviews per request, collected results in stable input order, and recorded explicit failures for reviews not submitted after request cancellation.
- Returned structured results that aggregate explicit denials separately from joined evaluation, API, and malformed-response errors; conclusive denials take precedence while errors remain available for logging.
- Added focused unit coverage for resource mapping, identity propagation, aggregated denial and error results, timeout handling, deduplication, and bounded concurrency.

## Phase 1 validation

- `MS_GOTOOLCHAIN_ALLOW_NON_LOCAL=1 GOTOOLCHAIN=auto go test -race ./pkg/utils/authorization` passed.
- `MS_GOTOOLCHAIN_ALLOW_NON_LOCAL=1 GOTOOLCHAIN=auto go vet ./pkg/utils/authorization` passed.
- Automatic toolchain selection was required because `go.mod` requires Go 1.26.6 while the installed local Microsoft Go toolchain is 1.26.5.

## References

- `pkg/utils/validator/placement.go` - shared CRP/RP admission validation.
- `pkg/webhook/clusterresourceplacement` - CRP mutating and validating webhooks.
- `pkg/webhook/resourceplacement` - RP validating webhook.
- `pkg/webhook/clusterresourceoverride` - CRO validating webhook.
- `pkg/webhook/resourceoverride` - RO validating webhook.
- `pkg/utils/controller/resource_selector_resolver.go` - current placement selector resolution semantics.
- `cmd/hubagent/options/featureflags.go` - hub-agent feature flag conventions.
- `charts/hub-agent/templates/rbac.yaml` - hub-agent service account permissions.
- No applicable specification directory exists under `.github/.copilot/`, and no selected-resource authorization entry was found in the domain knowledge files.
