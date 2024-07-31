#!/bin/bash

#
# Deploy Portworx StorageClass on an OCP cluster.
#

set -ex

# Prepare
readonly SCRIPT_DIR=$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")
readonly TOP_DIR=$(cd "${SCRIPT_DIR}"; git rev-parse --show-toplevel)

source "${TOP_DIR}"/ocp/common/funcs.sh
common::funcs::set_kubeconfig

# might change in the future to Enterprise
operator_name="Portworx Essentials"

oc apply --filename="${SCRIPT_DIR}/01_subscription.yaml" --overwrite

# Wait for subscription to be processed
install_plan=''; retries=0
while [[ -z "${install_plan}" ]]; do
  # Give up after 10 tries
  if ((retries == 10)); then
    echo "[ERROR] Timeout waiting for InstallPlan of ${operator_name} operator Subscription to be created." >&2
    exit 1
  fi

  sleep 30
  install_plan=$(
    oc get -f "${SCRIPT_DIR}/01_subscription.yaml" --output=jsonpath='{..installplan.name}'
  )

  ((retries += 1))
done

# Wait for the operator to be installed
oc wait installplan "${install_plan}" \
  --namespace='openshift-operators' \
  --for=condition='Installed' \
  --timeout='4m'

PORTWORX_CSV=$(
  oc get --filename="${SCRIPT_DIR}/01_subscription.yaml" \
    --output=jsonpath='{$.status.installedCSV}'
)

# Wait for CSV to be Ready
oc wait csv "${PORTWORX_CSV}" \
  --namespace='openshift-operators' \
  --for=jsonpath='{.status.phase}=Succeeded' \
  --timeout='5m'
