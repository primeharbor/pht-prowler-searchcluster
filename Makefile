# Copyright 2023-2024 Chris Farris <chrisf@primeharbor.com>
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

ifndef env
$(error env is not set)
endif

ifndef version
	export version := $(shell date +%Y%m%d-%H%M)
endif

ifndef PROWLER_VERSION
$(error PROWLER_VERSION is not set)
endif

IMAGENAME ?= prowler
DEPLOY_PREFIX ?= deploy-packages

CONTAINER_TAG ?= "v$(PROWLER_VERSION)-$(version)"


# Local to this Makefile Vars
PROWLER_TEMPLATE=cloudformation/Prowler-Template.yaml
PROWLER_OUTPUT_TEMPLATE_PREFIX=Prowler-Template-Transformed
PROWLER_OUTPUT_TEMPLATE=$(PROWLER_OUTPUT_TEMPLATE_PREFIX)-$(version).yaml
PROWLER_TEMPLATE_URL ?= https://s3.amazonaws.com/$(DEPLOY_BUCKET)/$(DEPLOY_PREFIX)/$(PROWLER_OUTPUT_TEMPLATE)

SCORECARD_TEMPLATE=cloudformation/Scorecards-Template.yaml
SCORECARD_OUTPUT_TEMPLATE_PREFIX=Scorecards-Template-Transformed
SCORECARD_OUTPUT_TEMPLATE=$(SCORECARD_OUTPUT_TEMPLATE_PREFIX)-$(version).yaml
SCORECARD_TEMPLATE_URL ?= https://s3.amazonaws.com/$(DEPLOY_BUCKET)/$(DEPLOY_PREFIX)/$(SCORECARD_OUTPUT_TEMPLATE)

OPENSEARCH_TEMPLATE=cloudformation/OpenSearch-Template.yaml
OPENSEARCH_OUTPUT_TEMPLATE_PREFIX=OpenSearch-Template-Transformed
OPENSEARCH_OUTPUT_TEMPLATE=$(OPENSEARCH_OUTPUT_TEMPLATE_PREFIX)-$(version).yaml
OPENSEARCH_TEMPLATE_URL ?= https://s3.amazonaws.com/$(DEPLOY_BUCKET)/$(DEPLOY_PREFIX)/$(OPENSEARCH_OUTPUT_TEMPLATE)

FINDINGS_TEMPLATE=cloudformation/RegionalFindings-Template.yaml
FINDINGS_OUTPUT_TEMPLATE_PREFIX=RegionalFindings-Template-Transformed
FINDINGS_OUTPUT_TEMPLATE=$(FINDINGS_OUTPUT_TEMPLATE_PREFIX)-$(version).yaml
FINDINGS_TEMPLATE_URL ?= https://s3.amazonaws.com/$(DEPLOY_BUCKET)/$(DEPLOY_PREFIX)/$(FINDINGS_OUTPUT_TEMPLATE)

#
# Prowler Container Targets
#
build:
	docker build --build-arg PROWLER_VERSION=$(PROWLER_VERSION) -t $(IMAGENAME) .

force-build:
	docker build --no-cache --build-arg PROWLER_VERSION=$(PROWLER_VERSION) -t $(IMAGENAME) .

build-gcp:
	docker build -t $(IMAGENAME) --build-arg PROWLER_VERSION=$(GCP_PROWLER_VERSION) -f Dockerfile-GCP .

force-build-gcp:
	docker build --no-cache -t $(IMAGENAME) --build-arg PROWLER_VERSION=$(GCP_PROWLER_VERSION)  -f Dockerfile-GCP .

run: stop
	docker run -it -v ./prowler-output:/home/prowler/prowler-output \
		-e AWS_DEFAULT_REGION -e AWS_SECRET_ACCESS_KEY -e AWS_ACCESS_KEY_ID -e AWS_SESSION_TOKEN \
		-e ROLENAME -e PAYER_ID -e GCP_CREDS -e OUTPUT_BUCKET \
		--entrypoint bash $(IMAGENAME)

list-checks-json: stop
	docker run -it --entrypoint prowler $(IMAGENAME) aws --list-checks-json

build-run: stop build run

list:
	docker images | grep $(IMAGENAME)

stop:
	$(eval ID := $(shell docker ps | grep $(IMAGENAME) | cut -d " " -f 1 ))
	@if [ ! -z $(ID) ] ; then docker kill $(ID) ; fi

repo:
	aws ecr create-repository --repository-name $(IMAGENAME)

push:
ifndef IMAGE_ID
	$(eval IMAGE_ID := $(shell docker images $(IMAGENAME):latest --format "{{.ID}}" ))
endif
	$(eval AWS_ACCOUNT_ID := $(shell aws sts get-caller-identity --query Account --output text ))
	aws ecr get-login-password --region $(AWS_DEFAULT_REGION) | docker login --username AWS --password-stdin $(AWS_ACCOUNT_ID).dkr.ecr.$(AWS_DEFAULT_REGION).amazonaws.com
	docker tag $(IMAGE_ID) $(AWS_ACCOUNT_ID).dkr.ecr.$(AWS_DEFAULT_REGION).amazonaws.com/$(IMAGENAME):$(CONTAINER_TAG)
	docker push $(AWS_ACCOUNT_ID).dkr.ecr.$(AWS_DEFAULT_REGION).amazonaws.com/$(IMAGENAME):$(CONTAINER_TAG)
	@echo "Now go set the IMAGE_VERSION to $(CONTAINER_TAG)"

container: build push
gcp-container: build-gcp push

#
# General Lambda / CFn targets
#
deps:
	cd lambda && $(MAKE) deps

#
# Prowler Deploy Commands
#
prowler-package: deps
	@aws cloudformation package --template-file $(PROWLER_TEMPLATE) --s3-bucket $(DEPLOY_BUCKET) --s3-prefix $(DEPLOY_PREFIX)/transform --output-template-file cloudformation/$(PROWLER_OUTPUT_TEMPLATE)  --metadata build_ver=$(version)
	@aws s3 cp cloudformation/$(PROWLER_OUTPUT_TEMPLATE) s3://$(DEPLOY_BUCKET)/$(DEPLOY_PREFIX)/
	rm cloudformation/$(PROWLER_OUTPUT_TEMPLATE)
	@echo "Deploy via $(PROWLER_TEMPLATE_URL)"

prowler-deploy: prowler-package
ifndef PROWLER_MANIFEST
	$(error PROWLER_MANIFEST is not set)
endif
	cft-deploy -m $(PROWLER_MANIFEST) --template-url $(PROWLER_TEMPLATE_URL) pTemplateURL=$(PROWLER_TEMPLATE_URL) pImageVersion=$(IMAGE_VERSION) --force

#
# Scorecard Deploy Commands
#
scorecard-deps:
	cd gsheet-lambda && $(MAKE) deps

scorecard-package: scorecard-deps
	@aws cloudformation package --template-file $(SCORECARD_TEMPLATE) --s3-bucket $(DEPLOY_BUCKET) --s3-prefix $(DEPLOY_PREFIX)/transform --output-template-file cloudformation/$(SCORECARD_OUTPUT_TEMPLATE)  --metadata build_ver=$(version)
	@aws s3 cp cloudformation/$(SCORECARD_OUTPUT_TEMPLATE) s3://$(DEPLOY_BUCKET)/$(DEPLOY_PREFIX)/
	rm cloudformation/$(SCORECARD_OUTPUT_TEMPLATE)
	@echo "Deploy via $(SCORECARD_TEMPLATE_URL)"

scorecard-deploy: scorecard-package
ifndef SCORECARD_MANIFEST
	$(error SCORECARD_MANIFEST is not set)
endif
	cft-deploy -m $(SCORECARD_MANIFEST) --template-url $(SCORECARD_TEMPLATE_URL) pTemplateURL=$(SCORECARD_TEMPLATE_URL) --force


#
# Opensearch Deploy Commands
#
opensearch-package: deps
	@aws cloudformation package --template-file $(OPENSEARCH_TEMPLATE) --s3-bucket $(DEPLOY_BUCKET) --s3-prefix $(DEPLOY_PREFIX)/transform --output-template-file cloudformation/$(OPENSEARCH_OUTPUT_TEMPLATE)  --metadata build_ver=$(version)
	@aws s3 cp cloudformation/$(OPENSEARCH_OUTPUT_TEMPLATE) s3://$(DEPLOY_BUCKET)/$(DEPLOY_PREFIX)/
	rm cloudformation/$(OPENSEARCH_OUTPUT_TEMPLATE)
	@echo "Deploy via $(OPENSEARCH_TEMPLATE_URL)"

opensearch-deploy: opensearch-package
ifndef SEARCH_MANIFEST
	$(error SEARCH_MANIFEST is not set)
endif
	cft-deploy -m $(SEARCH_MANIFEST) --template-url $(OPENSEARCH_TEMPLATE_URL) pTemplateURL=$(OPENSEARCH_TEMPLATE_URL) --force

#
# Regional Findings Deploy commands
#
findings-package: deps
	@aws cloudformation package --template-file $(FINDINGS_TEMPLATE) --s3-bucket $(DEPLOY_BUCKET) --s3-prefix $(DEPLOY_PREFIX)/transform --output-template-file cloudformation/$(FINDINGS_OUTPUT_TEMPLATE)  --metadata build_ver=$(version)
	@aws s3 cp cloudformation/$(FINDINGS_OUTPUT_TEMPLATE) s3://$(DEPLOY_BUCKET)/$(DEPLOY_PREFIX)/
	rm cloudformation/$(FINDINGS_OUTPUT_TEMPLATE)

findings-deploy: findings-package
ifndef FINDINGS_MANIFEST
	$(error FINDINGS_MANIFEST is not set)
endif
	cft-deploy -m cloudformation/$(FINDINGS_MANIFEST) --template-url $(FINDINGS_TEMPLATE_URL) pTemplateURL=$(FINDINGS_TEMPLATE_URL) --force


clean:
	cd lambda && $(MAKE) clean

#
# Bucket Import
#
prepare-import-bucket:
	aws cloudformation create-change-set --output text \
		--stack-name $(PROWLER_STACKNAME) \
		--change-set-name bucket-import \
		--parameters ParameterKey=pBucketName,ParameterValue=$(OUTPUT_BUCKET) \
		--template-body file://cloudformation/ProwlerBucket-ImportTemplate.yaml \
		--change-set-type IMPORT \
		--resources-to-import ResourceType=AWS::S3::Bucket,LogicalResourceId=ProwlerBucket,ResourceIdentifier={BucketName=$(OUTPUT_BUCKET)}
	@echo sleeping 30 seconds for changeset to execute
	aws cloudformation describe-change-set --change-set-name bucket-import --stack-name $(PROWLER_STACKNAME)
	@echo "If the Status is in CREATE_COMPLETE, you can perform `make execute-import-bucket`"

execute-import-bucket:
	aws cloudformation execute-change-set  --change-set-name bucket-import --stack-name $(PROWLER_STACKNAME)

# EOF