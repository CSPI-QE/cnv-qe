#!/bin/bash

#
# Deploy Portworx StorageCluster CR
# 
# Environment variables (typically set by a Jenkins Job):
# - ESSENTIAL_ENTITLEMENT_ID: Applicable only for Portworx Essentials. Can be retrieved from https://central.portworx.com/profile
#

set -ex

# Prepare
readonly SCRIPT_DIR=$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")
readonly TOP_DIR=$(cd "${SCRIPT_DIR}"; git rev-parse --show-toplevel)

source "${TOP_DIR}"/ocp/common/funcs.sh

common::funcs::set_kubeconfig

# "${WORKSPACE}/storagecluster.yaml" is assumed to be generated by another setup script, such as ocp/aws-ipi/portworx/setup_portworx.sh for example
STORAGECLUSTER_CR_FILE="${TOP_DIR}/storagecluster.yaml"
if [[ -f "${STORAGECLUSTER_CR_FILE}" ]]; then
    readonly STORAGECLUSTER_NAMESPACE=$(awk '/^\s+namespace:/ { print $2 }' "${STORAGECLUSTER_CR_FILE}" )
fi

if [[ ! -f "${STORAGECLUSTER_CR_FILE}" ]]; then
	echo "File ${STORAGECLUSTER_CR_FILE} not found"
    exit 1
fi

if [[ -z "${ESSENTIAL_ENTITLEMENT_ID}" ]]; then
	echo "ESSENTIAL_ENTITLEMENT_ID not defined."
    exit 1
fi

# This labeling is needed due to PSA
# This is needed regardless if the STORAGECLUSTER_NAMESPACE is kube-system or not, 
# since the portworx-proxy daemonset would reside in kube-system in case STORAGECLUSTER_NAMESPACE != kube-system
oc label ns kube-system pod-security.kubernetes.io/enforce=privileged

res=$(oc create namespace "${STORAGECLUSTER_NAMESPACE}" > /dev/null || true)

# Ignore already existing rule
if echo "$res" | grep -q "AlreadyExists"; then
  echo "Ignoring AlreadyExists error..."
elif [[ ! -z "$res" ]]; then
  echo "Error occurred: $res"
  exit 1
fi

# create secret for Portworx Essential
# TODO: remove if we will move in the future to Enterprise
# reference: https://docs.portworx.com/install-portworx/openshift/operator/2-deploy-px/#create-a-secret-for-portworx-essentials
USER_ID=$(echo -n "${ESSENTIAL_ENTITLEMENT_ID}" | base64 -w '0')
sed "${SCRIPT_DIR}/02_secret.yaml" \
    -e "s/__NAMESPACE__/${STORAGECLUSTER_NAMESPACE}/" \
    -e "s/__USER_ID__/${USER_ID}/" | oc apply --filename=-

oc apply --filename="${TOP_DIR}/storagecluster.yaml" --overwrite
sleep 60

# Wait for StorageCluster to be deployed
# reference: https://docs.portworx.com/install-portworx/openshift/rosa/aws-redhat-openshift/#verify-pxctl-cluster-provision-status
oc wait --filename="${TOP_DIR}/storagecluster.yaml"  \
  --for=condition=RuntimeState=Online \
  --timeout='10m'

oc wait -n "${STORAGECLUSTER_NAMESPACE}" storagenodes --all \
  --for=condition=NodeState=Online \
  --timeout='10m'

# Add RWX StorageClass
oc apply --filename="${SCRIPT_DIR}/03_shared_storageclass.yaml" --overwrite

oc apply -f - <<EOF
apiVersion: snapshot.storage.k8s.io/v1
kind: VolumeSnapshotClass
metadata:
  name: px-csi-snapclass
driver: pxd.portworx.com
deletionPolicy: Delete
EOF