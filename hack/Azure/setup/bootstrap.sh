export HUB_CLUSTER=hub
export MEMBER_CLUSTER_1=member-1
export MEMBER_CLUSTER_2=member-2
export MEMBER_CLUSTER_3=member-3
az account set -s ${SUBSCRIPTION_ID}
az group create --name ${RESOURCE_GROUP} --location ${LOCATION}
az aks create --resource-group ${RESOURCE_GROUP} --name ${HUB_CLUSTER} --location ${LOCATION} --node-count 2
az aks create --resource-group ${RESOURCE_GROUP} --name ${MEMBER_CLUSTER_1} --location ${LOCATION} --node-count 2
az aks create --resource-group ${RESOURCE_GROUP} --name ${MEMBER_CLUSTER_2} --location ${LOCATION} --node-count 2
az aks create --resource-group ${RESOURCE_GROUP} --name ${MEMBER_CLUSTER_3} --location ${LOCATION} --node-count 2


export REGISTRY="mcr.microsoft.com/aks/fleet"
export TAG=$(curl "https://api.github.com/repos/Azure/fleet/tags" | jq -r '.[0].name')

az aks get-credentials --resource-group ${RESOURCE_GROUP} --name ${HUB_CLUSTER} --overwrite-existing

helm install hub-agent charts/hub-agent/ \
  --set image.pullPolicy=Always \
  --set image.repository=$REGISTRY/hub-agent \
  --set image.tag=$TAG \
  --set logVerbosity=5 \
  --set namespace=fleet-system \
  --set enableWebhook=false \
  --set webhookClientConnectionType=service \
  --set enableV1Beta1APIs=true \
  --set clusterUnhealthyThreshold="3m0s" \
  --set forceDeleteWaitTime="1m0s" \
  --set resources.limits.cpu=4 \
  --set resources.limits.memory=4Gi \
  --set concurrentClusterPlacementSyncs=10 \
  --set ConcurrentRolloutSyncs=20 \
  --set hubAPIQPS=100 \
  --set hubAPIBurst=1000 \
  --set logFileMaxSize=5000 \
  --set MaxFleetSizeSupported=100

export HUB_CLUSTER_CONTEXT=$(kubectl config view -o jsonpath="{.contexts[?(@.name==\"$HUB_CLUSTER\")].name}")
export HUB_CLUSTER_ADDRESS=$(kubectl config view -o jsonpath="{.clusters[?(@.name==\"$HUB_CLUSTER\")].cluster.server}")

# Define member clusters
MEMBER_CLUSTERS=("$MEMBER_CLUSTER_1" "$MEMBER_CLUSTER_2" "$MEMBER_CLUSTER_3")

for MEMBER_CLUSTER_NAME in "${MEMBER_CLUSTERS[@]}"; do
  az aks get-credentials --resource-group "${RESOURCE_GROUP}" --name "${MEMBER_CLUSTER_NAME}" --overwrite-existing

  export MEMBER_CLUSTER=$(kubectl config view -o jsonpath="{.contexts[?(@.name==\"${MEMBER_CLUSTER_NAME}\")].name}")
  export MEMBER_CLUSTER_CONTEXT=$(kubectl config view -o jsonpath="{.contexts[?(@.name==\"${MEMBER_CLUSTER_NAME}\")].name}")

  export SERVICE_ACCOUNT="${MEMBER_CLUSTER}-hub-cluster-access"

  kubectl config use-context "${HUB_CLUSTER_CONTEXT}"
  kubectl create serviceaccount "${SERVICE_ACCOUNT}" -n fleet-system

  export SERVICE_ACCOUNT_SECRET="${MEMBER_CLUSTER}-hub-cluster-access-token"
  cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Secret
metadata:
    name: ${SERVICE_ACCOUNT_SECRET}
    namespace: fleet-system
    annotations:
        kubernetes.io/service-account.name: ${SERVICE_ACCOUNT}
type: kubernetes.io/service-account-token
EOF

  export TOKEN="$(kubectl get secret ${SERVICE_ACCOUNT_SECRET} -n fleet-system -o jsonpath='{.data.token}' | base64 --decode)"
  cat <<EOF | kubectl apply -f -
apiVersion: cluster.kubernetes-fleet.io/v1beta1
kind: MemberCluster
metadata:
    name: ${MEMBER_CLUSTER}
spec:
    identity:
        name: ${MEMBER_CLUSTER}-hub-cluster-access
        kind: ServiceAccount
        namespace: fleet-system
        apiGroup: ""
    heartbeatPeriodSeconds: 15
EOF

  kubectl config use-context "${MEMBER_CLUSTER_CONTEXT}"
  kubectl delete secret hub-kubeconfig-secret
  kubectl create secret generic hub-kubeconfig-secret --from-literal=token="${TOKEN}"

  helm uninstall member-agent --wait

  export MEMBER_AGENT_IMAGE="member-agent"
  export REFRESH_TOKEN_IMAGE="${REFRESH_TOKEN_NAME:-refresh-token}"

  helm install member-agent charts/member-agent/ \
    --set config.hubURL="${HUB_CLUSTER_ADDRESS}"  \
    --set image.repository="${REGISTRY}/${MEMBER_AGENT_IMAGE}" \
    --set image.tag="${TAG}" \
    --set refreshtoken.repository="${REGISTRY}/${REFRESH_TOKEN_IMAGE}" \
    --set refreshtoken.tag="${TAG}" \
    --set image.pullPolicy=Always \
    --set refreshtoken.pullPolicy=Always \
    --set config.memberClusterName="${MEMBER_CLUSTER}" \
    --set logVerbosity=5 \
    --set namespace=fleet-system \
    --set enableV1Beta1APIs=true

done

kubectl config use-context ${HUB_CLUSTER_CONTEXT}
echo "Setup completed."
