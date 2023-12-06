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


SEARCH_STACKNAME=$1
PROWLER_STACKNAME=$2

if [ -z $PROWLER_STACKNAME ] ; then
    echo "Usage: $0 SEARCH_STACKNAME PROWLER_STACKNAME"
    exit 1
fi

SECRET_ID=`aws cloudformation describe-stacks --stack-name ${SEARCH_STACKNAME} --output text --query "Stacks[0].Outputs[?OutputKey=='AdminLoginCredentials'].OutputValue" `
if [ -z $SECRET_ID ] ; then
    echo "Unable to find AdminLoginCredentials for Stack ${SEARCH_STACKNAME}. Aborting.."
    exit 1
fi

OSPASSWD=`aws secretsmanager get-secret-value --secret-id $SECRET_ID  --query SecretString --output text | jq -r .MasterUserPassword`
ENDPOINT=`aws cloudformation describe-stacks --stack-name ${SEARCH_STACKNAME} --output text --query "Stacks[0].Outputs[?OutputKey=='DomainEndpointURL'].OutputValue" `
ROLE=`aws cloudformation describe-stacks --stack-name ${PROWLER_STACKNAME} --output text --query "Stacks[0].Outputs[?OutputKey=='ProwlerRoleArn'].OutputValue" `

echo "Using Credentials from $SECRET_ID against $ENDPOINT to add $ROLE"
curl -XPUT -u admin:$OSPASSWD $ENDPOINT/_plugins/_security/api/rolesmapping/all_access -d '{"backend_roles": ["'$ROLE'"], "hosts": [], "users": ["admin"] }' -H 'Content-Type: application/json'
