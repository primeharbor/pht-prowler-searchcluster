#!/bin/bash

# Copyright 2023 Chris Farris <chris@primeharbor.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# if [ ! -x jq ] ; then
#     echo "jq not installed or not in path"
#     exit 1
# fi

STACKNAME=$1
if [ -z $STACKNAME ] ; then
    echo "Must specify STACKNAME"
    exit 1
fi


TASK_ID=`aws cloudformation describe-stack-resources --stack-name ${STACKNAME} --output text | grep ProwlerTaskDefinition | awk '{print $3}'`
if [ -z $TASK_ID ] ; then
    echo "Unable to find TASK_ID for Stack ${STACKNAME}. Aborting.."
    exit 1
fi

CLUSTER=`aws cloudformation describe-stack-resources --stack-name ${STACKNAME} --output text | grep ECSCluster | awk '{print $3}'`
if [ -z $CLUSTER ] ; then
    echo "Unable to find ECSCluster for Stack ${STACKNAME}. Aborting.."
    exit 1
fi

RULE_NAME=`aws cloudformation describe-stack-resources --stack-name ${STACKNAME} --output text | grep RunTaskRule | awk '{print $3}'`
if [ -z $RULE_NAME ] ; then
    echo "Unable to find RunTaskRule for Stack ${STACKNAME}. Aborting.."
    exit 1
fi

aws events list-targets-by-rule --rule $RULE_NAME --query 'Targets[0].EcsParameters.NetworkConfiguration' \
	| sed s/Subnets/subnets/g | sed s/SecurityGroups/securityGroups/g | sed s/AssignPublicIp/assignPublicIp/g > network.json
aws ecs run-task  --cluster $CLUSTER --task-definition $TASK_ID --launch-type="FARGATE" --network-configuration file://network.json --output text
rm network.json

