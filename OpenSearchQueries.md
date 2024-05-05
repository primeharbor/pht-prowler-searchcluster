# OpenSearch Queries for Prowler

## Big Gaping Security Holes
Big Gaping Security Holes are the extra critical findings that should be relatively easy to fix. These are ranked by my opinion of how bad they are


## Exposed Security Groups (Windows)
Exposed Ports on a Windows box are a recipe for becoming a Ransomware victim. Close these ports immediately
```
status_code: FAIL AND (
    finding_info.uid: "prowler-aws-ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_3389*" OR
    finding_info.uid: "prowler-aws-ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_sql_server_1433_1434*"
)
```

## Public Writable S3 Bucket
Public Writable S3 Buckets make you a [watering-hole risk](https://www.breaches.cloud/incidents/latimes/) for your consumers.
```
status_code: FAIL AND (
    finding_info.uid: "prowler-aws-s3_bucket_policy_public_write_access*" OR
    finding_info.uid: "prowler-aws-s3_bucket_public_write_acl*"
)
```

## Public CloudTrail Bucket!!!
I'm not sure I've ever actually seen this in the wild, but if I did I'd have bad indigestion.
```
status_code: FAIL AND finding_info.uid: "prowler-aws-cloudtrail_logs_s3_bucket_is_not_publicly_accessible*"
```

## EKS on the Internet
You probably don't want this
```
status_code: FAIL AND finding_info.uid: "prowler-aws-eks_endpoints_not_publicly_accessible*"
```

## Snapshots
You might have a legitimate reason to share an AMI to the world if you're a software vendor. Otherwise you probably have zero reason for sharing these to all AWS customers.
```
status_code: FAIL AND (
    finding_info.uid: "prowler-aws-rds_snapshots_public_access*" OR
    finding_info.uid: "prowler-aws-ec2_ebs_public_snapshot*" OR
    finding_info.uid: "prowler-aws-ec2_ami_public*"
)
```

## Public Listable S3 Bucket
This check looks for buckets that allow anyone or any AWS customer to view the contents. This makes it really easy for an attacker to look for something you don't intend to be public.
Sadly this check includes the ACL `READ_ACP` which allows anyone to see the ACLs on the bucket. That is less critical than the `READ` ACL, but `READ_ACP` has very limited purpose and should be removed too.
```
status_code: FAIL AND finding_info.uid: "prowler-aws-s3_bucket_public_list_acl*"
```

## Exposed Admin Ports (22/3389)
Similar to the above, this looks for public SSH and RDP. SSH is less sensitive, but clearly there are exploits in SSH and you should expose it sparingly.
```
status_code: FAIL AND (
    finding_info.uid: "prowler-aws-ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_3389*" OR
    finding_info.uid: "prowler-aws-ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22*"
)
```

## Wide open Security Groups
FIXME - what's the difference between these?
```
status_code: FAIL AND (
    finding_info.uid: "prowler-aws-ec2_securitygroup_allow_ingress_from_internet_to_any_port*" OR
    finding_info.uid: "prowler-aws-ec2_securitygroup_allow_wide_open_public_ipv4*"
)
```

## Root User Security
The root user has ultimate power. There is almost no reason to ever have root access keys or to use the root user.
Implementation of an SCP to block root user usage is an acceptable compensating control for iam_root_mfa_enabled, and if that is in place, remove the last line of this query.
```
status_code: FAIL AND (
    finding_info.uid: "prowler-aws-iam_no_root_access_key*" OR
    finding_info.uid: "prowler-aws-iam_avoid_root_usage*" OR
    finding_info.uid: "prowler-aws-iam_root_mfa_enabled*"
)
```

## IAM Users - Unused Access
Most breaches come from mishandled IAM Credentials. If they're not needed, you should remove them post-haste and reduce your risk surface.
```
status_code: FAIL AND (
    finding_info.uid: "prowler-aws-iam_user_console_access_unused*" OR
    finding_info.uid: "prowler-aws-iam_user_accesskey_unused*"
)
```

## IAM Console User w/o MFA
Console access should leverage identity federation, but there are cases for emergency break-glass IAM Users. These Users should have MFA.
```
status_code: FAIL AND finding_info.uid: "prowler-aws-iam_user_mfa_enabled_console_access*"
```

## Public S3 Buckets
You should review the Public S3 buckets in your environment to ensure they're supposed to be public.
Bonus points for enabling a Macie scan on public buckets to make sure no one shoved a Database backup from 2016 in a public bucket for convenance.
```
finding_info.uid: "prowler-aws-s3_bucket_public_access*" AND status_code: FAIL
```

## Subdomain TakeOver
These can happen when a resource is deleted and the route53 record pointing to it is not. These dangling references allow an attacker to re-create the resource under their control and make it look like a trusted resource.
```
status_code: FAIL AND finding_info.uid: "prowler-aws-route53_dangling_ip_subdomain_takeover*"
```

## Public Stuff
This check covers a number of resources that support Resource Policies that can be public.
```
status_code: FAIL AND (
    finding_info.uid: "prowler-aws-sns_topics_not_publicly_accessible*" OR
    finding_info.uid: "prowler-aws-sqs_queues_not_publicly_accessible*" OR
    finding_info.uid: "prowler-aws-kms_key_not_publicly_accessible*" OR
    finding_info.uid: "prowler-aws-awslambda_function_url_public*" OR
    finding_info.uid: "prowler-aws-awslambda_function_not_publicly_accessible*" OR
    finding_info.uid: "prowler-aws-ecr_repositories_not_publicly_accessible*" OR
    finding_info.uid: "prowler-aws-ssm_documents_set_as_public*"
    )
```


## Other Serious Issues that will take effort to resolve

## Ensure access keys are rotated every 90 days or less
Actively used access keys that are thousands of days old are often hard to find the person to rotate. You want to get a solid rotation process in place, but that takes effort and time.
```
finding_info.uid: "prowler-aws-iam_rotate_access_key_90_days*" AND status_code: FAIL
```

## Databases on the Internet
You probably don't want databases with sensitive data on the internet protected only by a username/password. That said, fixing this often requires re-creating the database, and is a lot of work.
```
status_code: FAIL AND (
    finding_info.uid: "prowler-aws-emr_cluster_master_nodes_no_public_ip*" OR
    finding_info.uid: "prowler-aws-neptune_cluster_uses_public_subnet*" OR
    finding_info.uid: "prowler-aws-rds_instance_no_public_access*" OR
    finding_info.uid: "prowler-aws-redshift_cluster_public_access*"
)
```

## Instances on the Internet
There are probably some cases where an EC2 instance needs direct access to the internet. But with the number of zero-days being exploited by ransomware groups, you want to limit this as much as possible.
```
status_code: FAIL AND finding_info.uid: "prowler-aws-ec2_instance_public_ip*"
```

# Secrets Detection
One feature of prowler over other CSPMs is that it attempts secrets detection

## Find all the secrets
```
status_code: FAIL AND (
    finding_info.uid: "prowler-aws-awslambda_function_no_secrets_in_variables *" OR
    finding_info.uid: "prowler-aws-autoscaling_find_secrets_ec2_launch_configuration*" OR
    finding_info.uid: "prowler-aws-cloudformation_stack_outputs_find_secrets*" OR
    finding_info.uid: "prowler-aws-cloudwatch_log_group_no_secrets_in_logs*" OR
    finding_info.uid: "prowler-aws-ec2_instance_secrets_user_data*" OR
    finding_info.uid: "prowler-aws-ecs_task_definitions_no_environment_secrets*" OR
    finding_info.uid: "prowler-aws-ssm_document_secrets*" OR
    finding_info.uid: "prowler-aws-awslambda_function_no_secrets_in_code*"
)
```


# Needed Prowler Checks

1. Public RDS - RDS has public IP _and_ Security Group that exposes the database port. - Resource is the Database
2. Exposed RDP - EC2 with Public IP, running Windows, with a SG that has 3389 open to the world - Resource is the Instance
3. Exposed Active Directory - Same as Exposed RDP, but using the Kerberos, LDAP, or CIFS ports. - Resource is the Instance
4. Exposed SSH - EC2 with Public IP, with a SG that has 22 open to the world. - Resource is the Instance
5. Block Public Access for AMI and Snapshots
6. Enforce IMDSv2

# All BGSH

status_code: FAIL AND (
    finding_info.uid: "prowler-aws-ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_3389*"
    OR finding_info.uid: "prowler-aws-ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_sql_server_1433_1434*"
    OR finding_info.uid: "prowler-aws-s3_bucket_policy_public_write_access*"
    OR finding_info.uid: "prowler-aws-s3_bucket_public_write_acl*"
    OR finding_info.uid: "prowler-aws-eks_endpoints_not_publicly_accessible*"
    OR finding_info.uid: "prowler-aws-rds_snapshots_public_access*"
    OR finding_info.uid: "prowler-aws-ec2_ebs_public_snapshot*"
    OR finding_info.uid: "prowler-aws-ec2_ami_public*"
    OR finding_info.uid: "prowler-aws-ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_3389*"
    OR finding_info.uid: "prowler-aws-ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22*"
    OR finding_info.uid: "prowler-aws-s3_bucket_public_list_acl*"
    OR finding_info.uid: "prowler-aws-iam_no_root_access_key*"
    OR finding_info.uid: "prowler-aws-iam_avoid_root_usage*"
    OR finding_info.uid: "prowler-aws-iam_root_mfa_enabled*"
    OR finding_info.uid: "prowler-aws-iam_user_mfa_enabled_console_access*"
    OR finding_info.uid: "prowler-aws-s3_bucket_public_access*"
    OR finding_info.uid: "prowler-aws-route53_dangling_ip_subdomain_takeover*"
)
