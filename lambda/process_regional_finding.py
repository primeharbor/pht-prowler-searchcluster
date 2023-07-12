# Copyright 2023 Chris Farris <chrisf@primeharbor.com>
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
from requests_aws4auth import AWS4Auth
import boto3
import json
import os
import requests
import datetime as dt

from common import *

import logging
logger = logging.getLogger()
logger.setLevel(getattr(logging, os.getenv('LOG_LEVEL', default='INFO')))
logging.getLogger('botocore').setLevel(logging.WARNING)
logging.getLogger('boto3').setLevel(logging.WARNING)
logging.getLogger('urllib3').setLevel(logging.WARNING)


org_details = get_org_account_details()

# Lambda execution starts here
def handler(event, context):
    logger.info("Received event: " + json.dumps(event, sort_keys=True))

    region = os.environ['AWS_REGION']
    service = 'es'
    credentials = boto3.Session().get_credentials()
    awsauth = AWS4Auth(credentials.access_key, credentials.secret_key, region, service, session_token=credentials.token)

    host = "https://{}".format(os.environ['ES_DOMAIN_ENDPOINT'])
    es_type = "_doc"  # This is what es is moving to after deprecating types in 6.0
    headers = {"Content-Type": "application/json"}

    bulk_ingest_body = ""
    count = 0

    # Only grab the detail from the event. The other stuff is related to the eventbridge event wraper
    finding_document = event['detail']

    if event['source'] == "aws.inspector2":
        if event["detail-type"] == "Inspector2 Coverage":
            logger.warning(f"Got an Inspector2 Coverage event")
            return(True)
        index = "inspector2"
        doc_id = f"{finding_document['findingArn']}"
        if finding_document['awsAccountId'] in org_details:
            finding_document['OrgInfo'] = org_details[finding_document['awsAccountId']]

        date_format = "%b %d, %Y, %I:%M:%S %p" # not sure why inspector v2 is non-standard
        keys_to_normalize = ['firstObservedAt', 'lastObservedAt', 'updatedAt' ]
        for k in keys_to_normalize:
            finding_document[k] = dt.datetime.strptime(finding_document[k], date_format).isoformat()

    elif event['source'] == "aws.access-analyzer":
        index = "access-analyzer"
        doc_id = f"{finding_document['findingArn']}"
        if finding_document['awsAccountId'] in org_details:
            finding_document['OrgInfo'] = org_details[finding_document['awsAccountId']]

    elif event['source'] == "aws.macie":
        index = "macie"
        doc_id = f"{finding_document['findingArn']}"
        if finding_document['awsAccountId'] in org_details:
            finding_document['OrgInfo'] = org_details[finding_document['awsAccountId']]

    elif event['source'] == "aws.guardduty":
        index = "guardduty2"
        doc_id = f"{finding_document['id']}"
        if finding_document['accountId'] in org_details:
            finding_document['OrgInfo'] = org_details[finding_document['accountId']]

    else:
        logger.warning(f"Got an unexpected Source: {event['source']}. Aborting")
        return(True)

    command = {"index": {"_index": index, "_id": doc_id}}
    command_str = json.dumps(command, separators=(',', ':'), default=str)
    document = json.dumps(finding_document, separators=(',', ':'), default=str)
    bulk_ingest_body += f"{command_str}\n{document}\n"
    count += 1
    bulk_ingest_body += "\n"

    # Don't call ES if there is nothing to do.
    if count == 0:
        logger.warning("No objects to index.")
        return(True)

    try:
        # Now index the document
        r = requests.post(f"{host}/_bulk", auth=awsauth, data=bulk_ingest_body, headers=headers)

        if not r.ok:
            logger.error(f"Bulk Error: {r.status_code} took {r.elapsed} sec - {r.text}")
            raise Exception

        else:  # We need to make sure all the elements succeeded
            response = r.json()
            logger.info(f"Bulk ingest of {count} documents request took {r.elapsed} sec and processing took {response['took']} ms with errors: {response['errors']}")
            if response['errors'] is False:
                return(True)  # all done here

            for item in response['items']:
                if 'index' not in item:
                    logger.error(f"Item {item} was not of type index. Huh?")
                    continue
                if item['index']['status'] != 201 and item['index']['status'] != 200:
                    logger.error(f"Bulk Ingest Failure: Index {item['index']['_index']} ID {item['index']['_id']} Status {item['index']['status']} - {item}")
                    # requeue_keys.append(process_requeue(item))

    except Exception as e:
        logger.critical(f"General Exception Indexing data: {e}")
        raise

