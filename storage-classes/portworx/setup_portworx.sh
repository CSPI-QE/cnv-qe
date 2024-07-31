#!/bin/bash

#
# Setup the environment before deploying Portworx on AWS cluster.
# - Create an IAM policy
# - Open ports for worker nodes
#
# Reference: https://docs.portworx.com/install-portworx/openshift/rosa/aws-redhat-openshift/#configure-your-environment

set -ex

readonly SCRIPT_DIR=$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")
readonly TOP_DIR=$(cd "${SCRIPT_DIR}"; git rev-parse --show-toplevel)

source "${TOP_DIR}"/ocp/common/funcs.sh

common::funcs::set_kubeconfig

INFRA_NAME=$(oc get infrastructures.config.openshift.io  cluster -ojsonpath={.status.infrastructureName})
WORKER_NODES_SG_NAME="${INFRA_NAME}-worker-sg"
WORKER_NODES_ROLE_NAME="${INFRA_NAME}-worker-role"

#WORKER_NODES_SG_ID=$(aws ec2 describe-security-groups \
#                        --filters="Name=tag:Name,Values=${WORKER_NODES_SG_NAME}" \
#                        --query="SecurityGroups[].GroupId" \
#                        --output text)
WORKER_NODES_SG_ID=$(aws ec2 describe-security-groups \
                        --group-name=${WORKER_NODES_SG_NAME}  \
                        --query="SecurityGroups[].GroupId" \
                        --output text)

cat > portworx-policy.json <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "",
            "Effect": "Allow",
            "Action": [
              "ec2:AttachVolume",
              "ec2:ModifyVolume",
              "ec2:DetachVolume",
              "ec2:CreateTags",
              "ec2:CreateVolume",
              "ec2:DeleteTags",
              "ec2:DeleteVolume",
              "ec2:DescribeTags",
              "ec2:DescribeVolumeAttribute",
              "ec2:DescribeVolumesModifications",
              "ec2:DescribeVolumeStatus",
              "ec2:DescribeVolumes",
              "ec2:DescribeInstances",
              "autoscaling:DescribeAutoScalingGroups"
            ],
            "Resource": [
              "*"
            ]
        }
    ]
}
EOF

aws iam put-role-policy \
  --role-name "${WORKER_NODES_ROLE_NAME}" \
  --policy-name portworx-sc-policy \
  --policy-document file://./portworx-policy.json

declare -A protocol_port_map
TCP_PORTS=("17001-17022" "20048" "111" "2049")
UDP_PORTS=("17002")
protocol_port_map=(
 ["tcp"]=TCP_PORTS[@]
 ["udp"]=UDP_PORTS[@]
)

for protocol in "${!protocol_port_map[@]}"; do
  for port in "${!protocol_port_map[$protocol]}"; do
    res=$(aws ec2 authorize-security-group-ingress \
          --group-id "${WORKER_NODES_SG_ID}" \
          --protocol $protocol \
          --port $port \
          --source-group "${WORKER_NODES_SG_ID}" > /dev/null || true)
    # Ignore already existing rule
    if echo "$res" | grep -q "InvalidPermission.Duplicate"; then
      echo "Ignoring InvalidPermission.Duplicate error..."
    elif [[ ! -z "$res" ]]; then
      echo "Error occurred: $res"
      exit 1
    fi
  done
done

# hardcoded for Essentials, since this name gets linked to an account, which is limited to 1 instance
# TODO: remove when/if we will get Enterprise license
STORAGE_CLUSTER_NAME="${INFRA_NAME}-fcb15c1b-9dbe-4d33-8bae-e10680b46bb6"

sed -e "s/__NAME__/${STORAGE_CLUSTER_NAME}/" \
    -e "s/__STORAGE_TYPE__/${STORAGE_TYPE:-gp3}/" \
    -e "s/__VOLUME_SIZE__/${VOLUME_SIZE:-150}/" \
    "${SCRIPT_DIR}/storagecluster.yaml" > "${TOP_DIR}/storagecluster.yaml"

# Create a monitoring ConfigMap
oc apply -f ${SCRIPT_DIR}/monitoring_config.yaml -n openshift-monitoring || true
oc get nodes -A || true