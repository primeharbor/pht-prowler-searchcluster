#!/usr/bin/env python3
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

from botocore.exceptions import ClientError
import boto3
import json
import os
import time

import logging
logger = logging.getLogger()
logger.setLevel(getattr(logging, os.getenv('LOG_LEVEL', default='INFO')))
logging.getLogger('botocore').setLevel(logging.WARNING)
logging.getLogger('boto3').setLevel(logging.WARNING)
logging.getLogger('urllib3').setLevel(logging.WARNING)


def main(args, logger):

    # list all accounts
    accounts = get_all_accounts()
    for a in accounts:
        account_id = a['Id']
        logger.info(f"Processing {a['Name']}({a['Id']})")

        creds = get_creds(args.role_name, account_id)
        regions = get_regions(creds)
        for r in regions:
            enable_prowler(args, creds, account_id, r)


def get_all_accounts():
    # Returns: [
    #         {
    #             'Id': 'string',
    #             'Arn': 'string',
    #             'Email': 'string',
    #             'Name': 'string',
    #             'Status': 'ACTIVE'|'SUSPENDED',
    #             'JoinedMethod': 'INVITED'|'CREATED',
    #             'JoinedTimestamp': datetime(2015, 1, 1)
    #         },
    #     ],
    org_client = boto3.client('organizations')
    try:
        output = []
        response = org_client.list_accounts(MaxResults=20)
        while 'NextToken' in response:
            output = output + response['Accounts']
            time.sleep(1)
            response = org_client.list_accounts(MaxResults=20, NextToken=response['NextToken'])

        output = output + response['Accounts']
        return(output)
    except ClientError as e:
        if e.response['Error']['Code'] == 'AWSOrganizationsNotInUseException':
            # This is a standalone account
            logger.error("This account is not part of an organization")
            exit(1)
        # This is what we get if we're a child in an organization, but not inventorying the payer
        elif e.response['Error']['Code'] == 'AccessDeniedException':
            logger.error("This is not an Organizational Administrator account or Delegated Admin")
            exit(1)
        else:
            raise


def enable_prowler(args, creds, account_id, region):
    sh_client = boto3.client('securityhub',
                             aws_access_key_id=creds['AccessKeyId'],
                             aws_secret_access_key=creds['SecretAccessKey'],
                             aws_session_token=creds['SessionToken'],
                             region_name = region)

    # Get the product arn
    product_arn = None
    product_paginator = sh_client.get_paginator('describe_products')
    for page in product_paginator.paginate():
        for p in page['Products']:
            if p['ProductName'].lower() == args.product_name.lower() and p['CompanyName'].lower() == args.company_name.lower():
                product_arn = p['ProductArn']

    if product_arn is None:
        logger.error(f"Unable to find Product arn for {args.company_name} {args.product_name} in {account_id}/{region}")
        exit(1)


    if args.disable:
        product_subscription_arn = None
        product_id = '/'.join(product_arn.split('/')[1:])
        response = sh_client.list_enabled_products_for_import()
        for s in response['ProductSubscriptions']:
            if s.endswith(product_id):
                product_subscription_arn = s

        if product_subscription_arn is None:
            logger.debug(f"Unable to find Product Subscription arn for {product_id} in {account_id}/{region}")
            return(True)
        else:
            response = sh_client.disable_import_findings_for_product(ProductSubscriptionArn=product_subscription_arn)
            if response['ResponseMetadata']['HTTPStatusCode'] != 200:
                logger.error(f"Issue disabling in {account_id}/{region}")
            else:
                logger.debug(f"Successfully disabled in {account_id}/{region}")
    else:
        try:
            response = sh_client.enable_import_findings_for_product(ProductArn=product_arn)
            if response['ResponseMetadata']['HTTPStatusCode'] != 200:
                logger.error(f"Issue enabling in {account_id}/{region}")
            else:
                logger.debug(f"Successfully enabled in {account_id}/{region}")
        except ClientError as e:
            if e.response['Error']['Code'] == "ResourceConflictException":
                logger.debug(f"Already enabled in {account_id}/{region}")
            else:
                logger.warning(f"Client Error enabling in {account_id}/{region}: {e}")

def get_regions(creds):
    """Return an array of the regions this account is active in. Ordered with us-east-1 in the front."""
    ec2 = boto3.client('ec2',
            aws_access_key_id = creds['AccessKeyId'],
            aws_secret_access_key = creds['SecretAccessKey'],
            aws_session_token = creds['SessionToken'])
    response = ec2.describe_regions()
    output = ['us-east-1']
    for r in response['Regions']:
        if r['RegionName'] == "us-east-1":
            continue
        output.append(r['RegionName'])
    return(output)


def get_creds(role_name, account_id, session_name=None):
    """
    Request temporary credentials for the account. Returns a dict in the form of
    {
        creds['AccessKeyId'],
        creds['SecretAccessKey'],
        creds['SessionToken']
    }
    Which can be passed to a new boto3 client or resource.
    Takes an optional session_name which can be used by CloudTrail and IAM
    Raises AntiopeAssumeRoleError() if the role is not found or cannot be assumed.
    """
    client = boto3.client('sts')
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"

    if session_name is None:
        session_name = "enable_prowler"

    try:
        session = client.assume_role(RoleArn=role_arn, RoleSessionName=session_name)
        return(session['Credentials'])
    except ClientError as e:
        logger.error(f"Failed to assume role {role_name} in account {account_id}: {e}")


def do_args():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--debug", help="print debugging info", action='store_true')
    parser.add_argument("--disable", help="Disable the Integration rather than enabling it", action='store_true')
    parser.add_argument("--product-name", help="Security Hub Product Name to enable", required=True)
    parser.add_argument("--company-name", help="Security Hub Product Company to enable", required=True)
    parser.add_argument("--role-name", help="Role Name to assume in each account", required=True)
    parser.add_argument("--role-session-name", help="RoleSessionName to use", default="enable_prowler_integration")
    args = parser.parse_args()

    return (args)


if __name__ == '__main__':

    args = do_args()

    # Logging idea stolen from: https://docs.python.org/3/howto/logging.html#configuring-logging
    # create console handler and set level to debug
    ch = logging.StreamHandler()
    if args.debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    # create formatter
    # formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    formatter = logging.Formatter('%(levelname)s - %(message)s')
    # add formatter to ch
    ch.setFormatter(formatter)
    # add ch to logger
    logger.addHandler(ch)

    main(args, logger)
