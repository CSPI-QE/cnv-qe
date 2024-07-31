#!/bin/bash

set -ex

readonly SCRIPT_DIR=$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")
readonly TOP_DIR=$(cd "${SCRIPT_DIR}"; git rev-parse --show-toplevel)

INFRA_NAME=$(oc get infrastructures.config.openshift.io  cluster -ojsonpath={.status.infrastructureName})
WORKER_NODES_SG_NAME="${INFRA_NAME}-worker-sg"
WORKER_NODES_ROLE_NAME="${INFRA_NAME}-worker-role"

aws ec2 create-security-group \
  --description "Create Custom Security Group" \
  --group-name ${WORKER_NODES_SG_NAME}

cat > trust-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Statement1",
      "Effect": "Allow",
      "Principal": {
         "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

#create the role if not exist
ROLE_EXISTS=$(aws iam list-roles --query "Roles[?RoleName=='$WORKER_NODES_ROLE_NAME'].RoleName" --output text)

# Check if the role exist
if [ "ROLE_EXISTS" == "WORKER_NODES_ROLE_NAME" ];
then
  echo "The role $WORKER_NODES_ROLE_NAME exists."
else
  aws iam create-role \
    --role-name ${WORKER_NODES_ROLE_NAME} \
    --assume-role-policy-document file://trust-policy.json
fi