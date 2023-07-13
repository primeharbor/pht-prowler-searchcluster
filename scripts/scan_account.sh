#!/bin/bash

if [[ -z "$ROLENAME" ]] ; then
        echo "ROLENAME not defined. Aborting..."
        exit 1
fi

if [[ -z "$OUTPUT_BUCKET" ]] ; then
        echo "OUTPUT_BUCKET not defined. Aborting..."
        exit 1
fi

if [[ -z "$PAYER_ID" ]] ; then
        echo "PAYER_ID not defined. Aborting..."
        exit 1
fi

ACCOUNT_ID=$1

if [[ -z "$ACCOUNT_ID" ]] ; then
        echo "Usage: $0 <account_id>"
        exit 1
fi

ulimit -n 4096

EXCLUDE_CHECKS="accessanalyzer_enabled accessanalyzer_enabled_without_findings cloudformation_stacks_termination_protection_enabled cloudtrail_kms_encryption_enabled ec2_networkacl_allow_ingress_any_port ec2_networkacl_allow_ingress_tcp_port_22 ec2_networkacl_allow_ingress_tcp_port_3389 iam_role_cross_service_confused_deputy_prevention iam_root_hardware_mfa_enabled s3_bucket_no_mfa_delete s3_bucket_server_access_logging_enabled s3_account_level_public_access_blocks iam_policy_allows_privilege_escalation inspector2_findings_exist shield_advanced_protection_in_route53_hosted_zones awslambda_function_no_secrets_in_code"

REGIONS="ap-south-1 eu-north-1 eu-west-3 eu-west-2 eu-west-1 ap-northeast-3 ap-northeast-2 ap-northeast-1     ca-central-1 sa-east-1 ap-southeast-1 ap-southeast-2 eu-central-1 us-east-1 us-east-2 us-west-1 us-west-2"

TODAY=`date +%Y-%m-%d`
START=`date +%s`

echo "Starting Scan of account $ACCOUNT_ID at epoch timestamp $START."
prowler aws -M csv json json-asff html  -b -z  \
        --excluded-services route53 cloudwatch  \
        -e $EXCLUDE_CHECKS \
        -f $REGIONS \
        --log-file prowler-logs-${ACCOUNT_ID}-${TODAY}.log \
        -F prowler-${ACCOUNT_ID}-${TODAY} --log-level ERROR \
        -R arn:aws:iam::$ACCOUNT_ID:role/$ROLENAME \
        -O arn:aws:iam::$PAYER_ID:role/$ROLENAME \
        -D ${OUTPUT_BUCKET} -o prowler-output 2> prowler-errors-${ACCOUNT_ID}-${TODAY}.log
RC=$?

END=`date +%s`
DUR=`expr $END - $START`

# aws s3 cp prowler-logs-${ACCOUNT_ID}-${TODAY}.log s3://${OUTPUT_BUCKET}/prowler-logs/
# aws s3 cp prowler-errors-${ACCOUNT_ID}-${TODAY}.log s3://${OUTPUT_BUCKET}/prowler-logs/
echo "Prowler Exited for $ACCOUNT_ID with error code $RC after $DUR seconds"
