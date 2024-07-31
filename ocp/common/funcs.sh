#!/hint/bash

# Append Artifactory pull-secret to the pull-secret.json
# Parameters:
#   pull_secret_file - path to the pull-secret.json file
append_artifactory_creds_to_pull_secret()
{
    local pull_secret_file="${1}"
    # When ARTIFACTORY_* variables are defined append it to the pull-secret.json
    if [[ -n "${ARTIFACTORY_SERVER}" && -n "${ARTIFACTORY_USER}" && -n "${ARTIFACTORY_TOKEN}" ]] ; then
        pull_sec=$(echo -n "${ARTIFACTORY_USER}:${ARTIFACTORY_TOKEN}" | base64 -w0)
        jq ".auths += {\"${ARTIFACTORY_SERVER}\": {\"auth\": \"${pull_sec}\"}}" \
            "${pull_secret_file}" > "${pull_secret_file}.new"
        # replace pull_secret_file with new content
        mv -f "${pull_secret_file}.new" ${pull_secret_file}
    fi
}

# Add pullSecret section to the installer configuration file.
#
# The secrets are copied from pull-secret.json file.
add_pull_secret()
{
    local pull_secret_file="cnv-qe-automation/ocp/common/pull-secret.json"
    append_artifactory_creds_to_pull_secret "${pull_secret_file}"
    # The sed snippet is used to have a proper YAML indentation by
    # adding two spaces at the beginning of each line from the json
    # file.
    cat >> "${CLUSTER_DIR}/install-config.yaml" << __EOF__
pullSecret: |-
$(sed -e 's/^/  /' "${pull_secret_file}")
__EOF__
}

# Add additionalTrustBundle section to the installer configuration file.
#
# The following certificates are copied from additional-trust-bundle.pem:
#   - Red Hat IT Root CA
add_additional_trust_bundle()
{
    # The sed snippet is used to have a proper YAML indentation by
    # adding two spaces at the beginning of each line from the json
    # file.
    cat >> "${CLUSTER_DIR}/install-config.yaml" << __EOF__
additionalTrustBundle: |-
$(sed -e 's/^/  /' cnv-qe-automation/ocp/common/additional-trust-bundle.pem)
__EOF__
}

# Set networking.networkType field in the installer configuration file.
#
# The value is taken from NETWORK_TYPE environment variable which should have
# been set by Jenkins OCP deployment job.
#
# Fallback to OVNKubernetes if the variable is not set.
set_network_type()
{
    sed -e "/networkType:/ s/.*/  networkType: ${NETWORK_TYPE:-OVNKubernetes}/" \
        -i "${CLUSTER_DIR}/install-config.yaml"
}

# Enable installation of a FIPS compliant cluster according to
# the value of the FIPS_ENABLED environment variable which should
# have been set by Jenkins OCP deployment job.
#
# This function must be invoked before running download-ocp-tools.sh
installer::set_fips_support()
{
  export OPENSHIFT_INSTALLER=${OPENSHIFT_INSTALLER:-'openshift-install'}

  if [[ ${FIPS_ENABLED^^} != 'TRUE' ]]; then
    return
  fi

  export OPENSHIFT_INSTALLER='openshift-install-fips'

  if [[ $(cat /proc/sys/crypto/fips_enabled) == 0 ]]; then
    export OPENSHIFT_INSTALL_SKIP_HOSTCRYPT_VALIDATION='1'
  fi
}

# Pause master and worker MCP.
#
# This function is useful to create multiple MachineConfigs in a row
# without having to wait for all nodes to be rebooted each time.
pause_mcp()
{
    oc patch --type=merge --patch='{"spec":{"paused": true}}' $(oc get mcp -o name)
}

# Resume master and worker MCP.
resume_mcp()
{
    oc patch --type=merge --patch='{"spec":{"paused": false}}' $(oc get mcp -o name)
}

reboot_node()
{
    local node=$1

    # IBM BM nodes deployed by UPI Ansible playbook
    if [[ $(is_ibmcloud_cluster) == 'TRUE' ]];
    then
        inventory_file="${TOP_DIR}/ocp/bm-upi/inventory/${CLUSTER_NAME}.${CLUSTER_DOMAIN}.yaml"
        if [[ ! -f "${inventory_file}" ]]; then
            echo_debug "Inventory file was not found for this cluster, I won't be able to reboot this node, sorry."
            return
        fi

        hostvars=$(ansible-inventory -i "${inventory_file}" --host "${node}")
        ipmi_address=$(echo "${hostvars}" | jq -r .ipmi_address)
        ipmi_username=$(echo "${hostvars}" | jq -r .ipmi_username)
        ipmi_password=$(echo "${hostvars}" | jq -r .ipmi_password)

        if [[ -z $ipmi_address || -z $ipmi_username || -z $ipmi_password ]]; then
          echo_debug "I don't have all the details to issue the ipmi command, one of this variables is missing"
          echo_debug "ipmi_address=${ipmi_address}"
          echo_debug "ipmi_username=${ipmi_username}"
          echo_debug "ipmi_password=${ipmi_password}"
          return
        fi

        ipmi_command="ipmitool -H ${ipmi_address} -U ${ipmi_username} -P ${ipmi_password} power reset"

        echo "Rebooting ${node} via IPMI command"
        ssh helper-node.${CLUSTER_NAME}.${CLUSTER_DOMAIN} -- "${ipmi_command}"

        return
    fi

    echo_debug "At the moment, there is no support for rebooting this cluster node."
}

check_if_a_node_stuck_on_boot()
{
    local mcp_stat_file="${1?Missing MCP status filename}"
    local max_counter=7

    oc get nodes --selector='!node-role.kubernetes.io/master,node-role.kubernetes.io/worker' \
      | awk '/(Not)?Ready,SchedulingDisabled/ {print $1}' >> "${mcp_stat_file}"

    local top_node=$(sort "${mcp_stat_file}" | uniq -c | sort -nr | head -1 | awk '{print $1,$2}')
    local counter=$(echo ${top_node} | awk '{print $1}')
    local node=$(echo ${top_node} | awk '{print $2}')

    if [[ $counter -ge $max_counter ]]; then
      reboot_node "${node}"
      sed -i "/${node}/d" "${mcp_stat_file}"
    fi

}

# Wait until master and worker MCP are Updated
# or timeout after 90min.
wait_mcp_for_updated()
{
    local attempts=${1:-60} i
    local mcp_updated="false"
    local mcp_stat_file="$(mktemp "${TMDIR:-/tmp}"/mcp-stat.XXXXX)"
    local ibmcloud_cluster="$(is_ibmcloud_cluster)"

    sleep 30

    for ((i=1; i<=attempts; i++)); do
      echo_debug "Attempt ${i}/${attempts}"
      sleep 30
      if oc wait mcp --all --for condition=updated --timeout=1m; then
        echo_debug "MCP is Updated"
        mcp_updated="true"
        break
      fi

      if [[ "${ibmcloud_cluster}" == 'TRUE' ]]; then
        check_if_a_node_stuck_on_boot "${mcp_stat_file}"
      fi
    done

    rm -f "${mcp_stat_file}"

    if [[ "${mcp_updated}" == "false" ]]; then
      echo_debug "Error: MCP didn't get Updated!!"
      exit 1
    fi
}

# Run a command until it succeeds or the maximum number of retries is reached.
#
# Arguments:
# - $1: a banner describing what we are waiting for
# - $2: the maximum number of retries before giving up
# - $3: the delay to wait before each retry
# - $@: the command to run
wait_for() {
  local what="$1"; shift
  local retries="$1"; shift
  local delay="$1"; shift

  echo "[INFO] Waiting for ${what}." >&2

  time (
    { set +x; } 2>/dev/null
    while true; do
      if "$@"; then
        break
      fi

      # Give up after too many tries
      if [[ "${retries}" -le 0 ]]; then
        echo "[ERROR] Timeout waiting for ${what}." >&2
        exit 1
      fi

      retries=$((retries - 1))
      sleep "${delay}"
    done
  )
}

echo_debug()
{
    echo "$@" >&2
}


# Generate cluster-nodes.yaml
generate_cluster_nodes_file() {
  local nodes_file="${CLUSTER_DIR}/$1"

  {
    echo '---'
    echo 'nodes:'
    openstack server list --name="${CLUSTER_ID}" -f yaml
  } >"${nodes_file}"

  # check if the command:
  #   openstack server list --name="${CLUSTER_ID}" -f yaml returns []
  # in case of empty list we need to the files to look like nodes: [] to be a valid yaml
  # which won't break the destroy job and ansible by reading not valid yaml file
  if grep -F "[]" "${nodes_file}"; then
    echo "nodes: []" > "${nodes_file}"
  else
    # Add the roles of each node since it can't be deduced from the node name
    # on SNO clusters
    # FIXME:
    # - find a smarter way
    oc get nodes --no-headers \
      | while read node unused roles unused; do
          sed -e "/Name: ${node}/ a \  Roles: [ ${roles} ]" \
              -i "${nodes_file}"
        done
  fi

  cp "${nodes_file}" "${WORKSPACE}"
}

### FIXME: hardcoded --filter-by-os linux/amd64
getImageDigest()
{
  local imageWithTag=$1
  # local imageDigest=$(skopeo inspect docker://${imageWithTag} --format "{{ .Digest }}")
  local REGISTRY_AUTH_FILE=${PULL_SECRET:-"${TOP_DIR}/ocp/common/pull-secret.json"}
  local imageDigest=$(oc -a ${REGISTRY_AUTH_FILE} image info "${imageWithTag}" --filter-by-os linux/amd64 -o json | jq -r .digest)

  echo "${imageDigest}"
}

convertImageTag2Digest()
{
  local imageWithTag=$1
  local imageDigest

  imageDigest=$(getImageDigest "${imageWithTag}")
  imageWithDigest=$(echo "${imageWithTag}" | awk -v imageDigest="${imageDigest}" -F':' '{printf("%s@%s",$1,imageDigest)}')

  echo "${imageWithDigest}"
}

# Wait for Package Manifests
wait_for_manifests() {
  local catalog_source="$1"
  local operator="$2"

  local retries=0
  while [ $retries -ne 10 ]; do
    if oc get packagemanifests --selector=catalog="${catalog_source}" | grep "${operator}"; then
      return
    fi
    sleep 30
    ((retries += 1))
  done
  echo "Error: didn't find packagemanifests." >&2
  return 1
}

# Create a Catalog Source
create_catalog_source() {
  local CS_NAME=$1
  local CS_IMAGE=$2
  local OCP_COMMON_DIR=$(readlink -f "$(dirname -- "${BASH_SOURCE[0]}")")

  if [[ ${DISCONNECTED_MODE^^} == "TRUE" ]]; then
    CS_IMAGE=$(convertImageTag2Digest ${CS_IMAGE})
  fi

  sed "${OCP_COMMON_DIR}/templates/catalog_source.yaml" \
    -e "s|^\( \+name\): .*|\1: ${CS_NAME}|" \
    -e "s|^\( \+image\): .*|\1: ${CS_IMAGE}|" \
    -e "s|^\( \+displayName\): .*|\1: ${CS_NAME}|" \
    | oc apply --overwrite -f -

  # Wait for the CatalogSource to be ready
  sleep 30
  oc wait catalogsource "${CS_NAME}" \
    --namespace='openshift-marketplace' \
    --for=jsonpath='{.status.connectionState.lastObservedState}=READY' \
    --timeout='5m' \
  || {
    echo "[ERROR] Timeout waiting for the CatalogSource ${CS_NAME} to be Ready." >&2
    exit 1
  }
}

# Generate deploydata.json in the CLUSTER_DIR.
# Inputs: provider name
deploydata::generate() {
    local PROVIDER="$1"
    python3 "${TOP_DIR}/ocp/common/deploydata.py" \
        --provider "${PROVIDER}" > "${CLUSTER_DIR}/deploydata.json"
}

# Add the clusterId to the deploydata.json
# Inputs: Cluster ID
deploydata::append_clusterid() {
    local CLUSTER_ID="${1}"
    local DD_JSON_PATH="${CLUSTER_DIR}/deploydata.json"
    jq ".clusterID = \"${CLUSTER_ID}\"" "${DD_JSON_PATH}" > "${DD_JSON_PATH}.new"
    mv -f "${DD_JSON_PATH}.new" "${DD_JSON_PATH}"
}

# Returns the latest GA redhat-operators catalog source in the cluster.
#
# If there is catalogSource with the label latest-ga-redhat-operators that
# means that we are using the pre-GA openshift version and we will use
# this catalog source for our operators.
#
# In case we don't find such catalogSource with such label we
# use redhat-operators instead.
#
# Output: catalog source name
get_redhat_operators_catalog_source() {
  local DISCONNECTED_MODE=${DISCONNECTED_MODE:-'FALSE'}
  local catalog=$(
    oc get catalogsource \
      -n openshift-marketplace \
      --selector=latest-ga-redhat-operators=true \
      -o jsonpath="{.items[*].metadata.name}")
  if [[ -z "${catalog}" ]] ; then
    # Current OpenShift version is already GA, using redhat-operators
    catalog="redhat-operators"

    if [[ -n "${DISCONNECTED_MODE:-}" ]] \
    && [[ "${DISCONNECTED_MODE^^}" == "TRUE" ]]
    then
      catalog="local-${catalog}"
    fi
  fi

  echo "${catalog}"
}

# Returns the latest GA certified-operators catalog source in the cluster.
#
# If there is catalogsource with the label latest-ga-certified-operators that
# means that we are using the pre-GA openshift version and we will use
# this catalog source for our operators.
#
# In case we don't find such catalogsource with such label we
# use redhat-operators instead.
#
# Ouput: catalog source name
get_certified_operators_catalog_source() {
  local DISCONNECTED_MODE=${DISCONNECTED_MODE:-'FALSE'}
  local catalog=$(
    oc get catalogsource \
      -n openshift-marketplace \
      --selector=latest-ga-certified-operators=true \
      -o jsonpath="{.items[*].metadata.name}")
  if [[ -z "${catalog}" ]] ; then
    # Current OpenShift version is already GA, using certified-operators
    catalog="certified-operators"

    if [[ -n "${DISCONNECTED_MODE:-}" ]] \
    && [[ "${DISCONNECTED_MODE^^}" == "TRUE" ]]
    then
      catalog="local-${catalog}"
    fi
  fi

  echo "${catalog}"
}

# Returns the catalog source containing "pre-release" builds of redhat-operators:
# - before OCP GA, redhat-operators-art catalog source should be created in
#   post-create cluster script and will be returned by this function
# - after OCP GA, redhat-operators-art catalog source is not updated anymore and
#   should be removed from  post-create cluster script and default redhat-operators
#   catalog source will be returned by this function.
get_redhat_operators_art_catalog_source() {
  local catalog

  if oc get catalogsource -n openshift-marketplace redhat-operators-art &>/dev/null; then
    catalog='redhat-operators-art'
  else
    catalog='redhat-operators'
  fi

  echo "${catalog}"
}

# exports KUBECONFIG if CLUSTER_DOMAIN and CLUSTER_NAME is given,
# otherwise we assume the kubeconfig is set by user in different location
common::funcs::set_kubeconfig() {
  if [[ -n "${CLUSTER_DOMAIN:-}" ]] && [[ -n "${CLUSTER_NAME:-}" ]]; then
    readonly CLUSTER_DIR="${HOME}/${CLUSTER_DOMAIN}/${CLUSTER_NAME}"
    export KUBECONFIG="${CLUSTER_DIR}/auth/kubeconfig"
  fi
}

#
# Set default storage
#
# Inputs:
#   * storageclass - name of the storageclass to be default
storageclass::set_default() {
  local storageclass="${1}"
  # Using a W/A - bug: https://bugzilla.redhat.com/show_bug.cgi?id=2079830
  #oc annotate storageclasses --all storageclass.kubernetes.io/is-default-class-
  #oc annotate storageclass "${storageclass}" storageclass.kubernetes.io/is-default-class=true
  oc get storageclass -o name | xargs oc patch -p '{"metadata": {"annotations": {"storageclass.kubernetes.io/is-default-class": "false"}}}'
  oc patch storageclass "${storageclass}" -p '{"metadata": {"annotations": {"storageclass.kubernetes.io/is-default-class": "true"}}}'
  echo "[DEBUG] Printing Storage Classes:"
  oc get storageclasses
}

#
# Set default virt storage
#
# Inputs:
#   * storageclass - name of the storageclass to be default
storageclass::set_virt_default() {
  local storageclass="${1}"
  oc get storageclass -o name | xargs oc patch -p '{"metadata": {"annotations": {"storageclass.kubevirt.io/is-default-virt-class": "false"}}}'
  oc patch storageclass "${storageclass}" -p '{"metadata": {"annotations": {"storageclass.kubevirt.io/is-default-virt-class": "true"}}}'
}

#
# Enable or disable HCO feature gate
#
# Inputs:
#   * featuregate - name of the feature gate
#   * status - true / false
cnv::toggle_feature_gate () {
  local featuregate="${1}"
  local status="${2}"
  oc patch hco kubevirt-hyperconverged -n openshift-cnv \
    --type=merge \
    -p "{\"spec\":{\"featureGates\": {\"${featuregate}\": ${status}}}}"
  oc wait hco kubevirt-hyperconverged -n openshift-cnv  \
    --for=condition='Available' \
    --timeout='5m'
}

#
# Re-import datavolumes, for example after changing the default storage class
#
cnv::reimport_datavolumes(){
  local dvnamespace="openshift-virtualization-os-images"
  echo "[DEBUG] Disable DataImportCron"
  cnv::toggle_feature_gate "enableCommonBootImageImport" "false"
  sleep 1
  oc wait dataimportcrons -n "${dvnamespace}" --all --for='delete'
  echo "[DEBUG] Delete all DataSources, DataVolumes, VolumeSnapshots and PVCs of CNV default volumes"
  oc delete datasources,datavolumes,volumesnapshots,pvc -n "${dvnamespace}" --selector='cdi.kubevirt.io/dataImportCron'
  echo "[DEBUG] Enable DataImportCron"
  cnv::toggle_feature_gate "enableCommonBootImageImport" "true"
  sleep 10
  echo "[DEBUG] Wait for DataImportCron to re-import volumes"
  oc wait DataImportCron -n "${dvnamespace}" --all --for=condition=UpToDate --timeout=20m
  echo "[DEBUG] Printing persistent volume claims"
  oc get pvc -n "${dvnamespace}"
}

cnv::get_iib_image(){
  local iib_image="${1}"
  local cnv_version="${2}"
  local cnv_source="${3}"
  local script_dir=$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")
  local top_dir=$(cd "${script_dir}"; git rev-parse --show-toplevel)
  local iib_osbs_map_file="${top_dir}/cnv/iib-osbs-map.json"
  local iib_stage_map_file="${top_dir}/cnv/iib-stage-map.json"
  local iib_gate_map_file="${top_dir}/cnv/iib-gate-map.json"

    # IIB_IMAGE set by Jenkins job parameters has higher priority
  if [[ -z "${iib_image}" ]]; then

    case ${cnv_source} in
      osbs)
        iib_image="$(jq -r "if has(\"${cnv_version}\") then
                              .\"${cnv_version}\".image
                            else
                              error(\"Unknown CNV_VERSION: ${cnv_version}\")
                            end" "${iib_osbs_map_file}")"
        ;;
      osbs-post-gating)
        iib_image="$(jq -r "if has(\"${cnv_version}\") then
                              .\"${cnv_version}\".image
                            else
                              error(\"Unknown CNV_VERSION: ${cnv_version}\")
                            end" "${iib_gate_map_file}")"
        ;;
      stage)
        iib_image="$(jq -r "if has(\"${cnv_version}\") then
                              .\"${cnv_version}\".image
                            else
                              error(\"Unknown CNV_VERSION: ${cnv_version}\")
                            end" "${iib_stage_map_file}")"
        ;;
      pre-release)
        iib_image="quay.io/openshift-cnv/nightly-catalog:${cnv_version%.*}"
        ;;
    esac
  fi

  # Deploy CNV from public brew registry on all platforms
  if [[ ! -z "${iib_image}" && ("${cnv_source}" == 'osbs' || "${cnv_source}" == 'osbs-post-gating' || "${cnv_source}" == 'stage') ]]; then
    iib_image="brew.registry.redhat.io/rh-osbs/${iib_image##*/}"
  fi

  echo $iib_image
}

#
# A function to test if we running the deployment for a IBM Cluster
# Return TRUE/FALSE based on the domain we use
#
is_ibmcloud_cluster()
{
  local IBM_CLUSTERS_MATCH="ibmc(-upi)?\.cnv-qe\.rhood\.us$"

  [[ -z ${CLUSTER_DOMAIN:-} ]] && CLUSTER_DOMAIN=${1:-}

  if [[ "${CLUSTER_DOMAIN}" =~ ${IBM_CLUSTERS_MATCH} ]]
  then
    echo 'TRUE'
    return
  fi

  echo 'FALSE'
}

create_namespace() {
  local namespace=${1?"Missing argument"}

  cat << EOF | oc apply -f -
apiVersion: v1
kind: Namespace
metadata:
  name: ${namespace}
EOF

}

create_operator_group() {
  local name=${1?Missing Name}
  local namespace=${2?Missing Namespace}

  cat << EOF | oc apply -f -
apiVersion: operators.coreos.com/v1
kind: OperatorGroup
metadata:
  name: ${name}
  namespace: ${namespace}
EOF
}


wait_for_subscription_or_abort() {

  local subscription_yaml_file=${1?Missing path to subscription yaml}
  local timeout=${2:-'5m'}
  local namespace

  if [[ ! -r ${subscription_yaml_file} ]]; then
    echo_debug "Failed to read subscription yaml file"
    exit 1
  fi

  if command -v yq &> /dev/null
  then
    # safer
    namespace=$(yq -r .metadata.namespace "${subscription_yaml_file}")
  else
    # fall back if we don't have yq installed
    namespace=$(awk -F' ' '/^ +namespace:/ {print $2; exit}' "${subscription_yaml_file}")
  fi

  # Wait for subscription to be processed
  install_plan=''; retries=0
  while [[ -z "${install_plan}" ]]; do
    # Give up after 10 tries
    if ((retries == 10)); then
      echo_debug "[ERROR] Timeout waiting for InstallPlan to be created."
      exit 1
    fi

    sleep 30
    install_plan=$(
      oc get -f "${subscription_yaml_file}" --output=jsonpath='{..installplan.name}'
    )

    ((retries += 1))
  done

  # Wait for operator to be installed
  oc wait installplan "${install_plan}" \
    --namespace="${namespace}" \
    --for=condition='Installed' \
    --timeout="${timeout}"
  sleep 5
}

print_csv_version() {

  local subscription_name=${1?Missing subscription name}
  local namespace=${2?Missing namespace}

  local CSV_NAME=$(oc get subscription -n ${namespace} "${subscription_name}" -o jsonpath="{.status.installedCSV}")
  local INSTALLED_VERSION=$(oc get csv -n ${namespace} ${CSV_NAME} -o jsonpath="{.spec.version}")

  set +x
  echo "--------------------------------------------------------------------------------"
  echo "Operator Version: ${INSTALLED_VERSION}"
  echo "--------------------------------------------------------------------------------"

}

#
# A function to set an appropriate permissions for the cluster dir
# Takes path to the cluster-dir as a parameter.
#
cluster_dir::set_permission () {
  local clusterdir="$1"

  chmod -R o+r "${clusterdir}"
  # Ensure that kubeconfig can be readby other users (for example: cnv-qe-jenkins)
  chmod o+rx "${clusterdir}/auth"
  chmod go+rw "${clusterdir}/auth/kubeconfig"
  sync "${clusterdir}"
}

get_yq() {
  YQ_LATEST_VERSION=$(curl -fsSL -H 'Accept: application/json' https://github.com/mikefarah/yq/releases/latest | jq -r .tag_name)
  if [[ "${YQ_LATEST_VERSION}" == "null" ]]; then
    YQ_LATEST_VERSION="v4.43.1"
  fi
  curl -Lo yq "https://github.com/mikefarah/yq/releases/download/${YQ_LATEST_VERSION}/yq_linux_amd64"
  chmod +x yq
}

#
# Wipe all the disks *not* used by RHCOS for each node of the cluster.
#
storage::wipe_data_disks() {
  local node

  for node in $(oc get nodes -o name); do

    oc debug "${node}" -- chroot /host /bin/bash -exuc '
      # Get the disk used by RHCOS
      root=$(findmnt -M / -nv -o source)
      rhcos_disk=$(lsblk "${root}" -nd -o pkname)

      # Wipe all disks not used by RHCOS
      lsblk -bdnr -o name,rm,ro,size \
      | while read -r name removable read_only size; do
        # Exclude RHCOS disk and Ceph devices
        case "${name}" in
            ${rhcos_disk}) continue;;
            rbd*) continue;;
            loop*) continue;;
            nbd*) continue;;
        esac

        # Exclude removable devices
        [[ "${removable}" = 1 ]] && continue

        # Exclude read-only devices
        [[ "${read_only}" = 1 ]] && continue

        # Exclude 0 size devices
        [[ "${size}" = 0 ]] && continue

        data_disk=/dev/${name}

        # Remove LVM leftovers
        for pv in $(pvs --noheadings -o pv_name | grep -F "${data_disk}"); do
          vg=$(pvs --noheadings -o vg_name "${pv}" | awk "{ print(\$1) }")
          lvremove -ff "${vg}"
          vgremove -fy "${vg}"
          pvremove -fy "${pv}"
        done

        wipefs -af "${data_disk}"
        blockdev --rereadpt "${data_disk}"
      done
    '

  done
}

disable_provisioning_network() {
  # Disable the provisioning feature of baremetal operator so that it won't
  # conflict with the Ironic stack of the bootstrap VM and it won't prevent to
  # deploy other clusters in the same network.
  oc patch provisioning.metal3 provisioning-configuration \
    --type='merge' \
    --patch='{
      "spec": {
        "provisioningNetwork": "Disabled"
      }
    }'

  # Give some time to the Ironic stack to shutdown
  sleep '2m'
}

convert_icsp_to_idms(){
  local icsp_file=${1}
  local idms_files=()
  rm -f final_idms.yml
  touch final_idms.yml
  if [[ ! -f "yq" ]]; then
    get_yq
  fi
  # Split ICSP documents to separate files
  ./yq -s '"icsp" + $index' $icsp_file
  # Convert each file to IDMS
  for icsp_file in $(find ~+ -name 'icsp[0-9]*.yml'); do
    idms_files+=($(oc adm migrate icsp $icsp_file | cut -d " " -f4))
    rm -f $icsp_file
  done
  # Merge resulting documents into a single YAML file
  for idms_file in "${idms_files[@]}"; do
    echo "---" >> final_idms.yml
    cat $idms_file >> final_idms.yml
    rm -f $idms_file
  done
  # Echo resulting file full path
  echo $PWD/final_idms.yml
}

is_cluster_using_idms(){
  local cluster_ICSP=$(oc get imagecontentsourcepolicy 2>/dev/null)
  local cluster_y_version=$(oc get clusterversions version -o jsonpath='{.status.desired.version}' | cut -d '.' -f2)
  if [[ $cluster_y_version -ge 13 ]]; then
    # Checking if ICSP is NOT used already in the cluster
    if [[ $cluster_ICSP == "" ]]; then
      # Using IDMS
      return 0
    fi
  fi
  # Using ICSP
  return 1
}

get_mirror_policy_file(){
  # Accepts ICSP filepath
  # Checks if the file provided needs conversion to IDMS, converts and prints IDMS filepath
  local policy_file=${1}
  if is_cluster_using_idms; then
    policy_file=$(convert_icsp_to_idms $policy_file)
  fi
  echo $policy_file
}

apply_mirroring() {
  local CONTROL_PLANE_TOPOLOGY=$(oc get infrastructure cluster -o=jsonpath='{$.status.controlPlaneTopology}')
  local POLICY_FILE=$(get_mirror_policy_file "${TOP_DIR}/data/image_sources/global_icsp.yaml")
  if [[ ${DISCONNECTED_MODE^^} != "TRUE" ]]; then
    # IIB images built by OSBS require to generate an ImageContentSourcePolicy
    # mapping images referenced in the IIB image.
    # In case of an hypershift guest cluster, there is no MachineConfig and ISCP is
    # already configured at the HostedCluster.spec.imageContentSources
    if [[ "${CNV_SOURCE}" != 'pre-release' ]]; then
      if [[ ${CONTROL_PLANE_TOPOLOGY} != "External" ]]; then
        pause_mcp
        oc delete --filename="${POLICY_FILE}" --ignore-not-found
        oc create --filename="${POLICY_FILE}"
        resume_mcp
        sleep 30
        wait_mcp_for_updated
      elif [[ -n ${INFRA_KUBECONFIG} ]]; then
        if [[ ! -f "yq" ]]; then
            get_yq
        fi
        ./yq e '.spec | select(.repositoryDigestMirrors, .imageDigestMirrors) | .[]' "${POLICY_FILE}" > mirror_policy.yaml
        ./yq --null-input '.spec.imageContentSources += load("mirror_policy.yaml")' > "${SCRIPT_DIR}/cnv_mirror_manifests/hostedcluster.yaml"
        oc --kubeconfig "${INFRA_KUBECONFIG}" patch hostedcluster ${CLUSTER_NAME} -n clusters --type merge --patch-file "${SCRIPT_DIR}/cnv_mirror_manifests/hostedcluster.yaml"
        rm -rf "${SCRIPT_DIR}/cnv_mirror_manifests"
      fi
    fi
  fi
}
