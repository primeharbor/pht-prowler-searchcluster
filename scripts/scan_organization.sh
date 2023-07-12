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

ulimit -n 4096

EXCLUDE_CHECKS="accessanalyzer_enabled accessanalyzer_enabled_without_findings cloudformation_stacks_termination_protection_enabled cloudtrail_kms_encryption_enabled ec2_networkacl_allow_ingress_any_port ec2_networkacl_allow_ingress_tcp_port_22 ec2_networkacl_allow_ingress_tcp_port_3389 iam_role_cross_service_confused_deputy_prevention iam_root_hardware_mfa_enabled s3_bucket_no_mfa_delete s3_bucket_server_access_logging_enabled s3_account_level_public_access_blocks iam_policy_allows_privilege_escalation inspector2_findings_exist shield_advanced_protection_in_route53_hosted_zones"

TODAY=`date +%Y-%m-%d`

while read line ; do

	START=`date +%s`
	# extract the values we need
	ACCOUNT_ID=`echo $line | awk '{print $1}'`
	ACCOUNT_STATUS=`echo $line | awk '{print $2}'`

	if [ -f prowler-output/prowler-${ACCOUNT_ID}-${TODAY}.csv ] ; then
		echo "$ACCOUNT_ID was already scanned on $TODAY"
		continue
	fi

	echo "Starting Scan of account $ACCOUNT_ID at epoch timestamp $START."
	prowler aws -M csv json json-asff html  -b -z  \
		--excluded-services route53 cloudwatch  \
		-e $EXCLUDE_CHECKS \
		--log-file prowler-logs-${ACCOUNT_ID}-${TODAY}.log \
		-F prowler-${ACCOUNT_ID}-${TODAY} --log-level ERROR \
		-R arn:aws:iam::$ACCOUNT_ID:role/$ROLENAME \
		-O arn:aws:iam::$PAYER_ID:role/$ROLENAME \
		-D ${OUTPUT_BUCKET} -o prowler-output 2> prowler-errors-${ACCOUNT_ID}-${TODAY}.log
	RC=$?

	END=`date +%s`
	DUR=`expr $END - $START`

	aws s3 cp prowler-logs-${ACCOUNT_ID}-${TODAY}.log s3://${OUTPUT_BUCKET}/prowler-logs/
	aws s3 cp prowler-errors-${ACCOUNT_ID}-${TODAY}.log s3://${OUTPUT_BUCKET}/prowler-logs/
	echo "Prowler Exited for $ACCOUNT_ID with error code $RC after $DUR seconds"

done < <(aws organizations list-accounts --query Accounts[].[Id,Status] --output text | grep ACTIVE )