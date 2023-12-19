# Copyright 2023 - Chris Farris (chris@primeharbor.com) - All Rights Reserved
#

ifndef env
$(error env is not set)
endif

include config.$(env)
export

ifndef version
	export version := $(shell date +%Y%m%d-%H%M)
endif

IMAGENAME ?= prowler
DEPLOY_PREFIX ?= deploy-packages

# Local to this Makefile Vars
PROWLER_TEMPLATE=cloudformation/Prowler-Template.yaml
PROWLER_OUTPUT_TEMPLATE_PREFIX=Prowler-Template-Transformed
PROWLER_OUTPUT_TEMPLATE=$(PROWLER_OUTPUT_TEMPLATE_PREFIX)-$(version).yaml
PROWLER_TEMPLATE_URL ?= https://s3.amazonaws.com/$(DEPLOY_BUCKET)/$(DEPLOY_PREFIX)/$(PROWLER_OUTPUT_TEMPLATE)

FINDINGS_TEMPLATE=cloudformation/RegionalFindings-Template.yaml
FINDINGS_OUTPUT_TEMPLATE_PREFIX=RegionalFindings-Template-Transformed
FINDINGS_OUTPUT_TEMPLATE=$(FINDINGS_OUTPUT_TEMPLATE_PREFIX)-$(version).yaml
FINDINGS_TEMPLATE_URL ?= https://s3.amazonaws.com/$(DEPLOY_BUCKET)/$(DEPLOY_PREFIX)/$(FINDINGS_OUTPUT_TEMPLATE)

#
# Prowler Container Targets
#
build:
	docker build -t $(IMAGENAME) .

force-build:
	docker build --no-cache -t $(IMAGENAME) .

run: stop
	docker run -it -v ./prowler-output:/home/prowler/prowler-output \
		-e AWS_DEFAULT_REGION -e AWS_SECRET_ACCESS_KEY -e AWS_ACCESS_KEY_ID -e AWS_SESSION_TOKEN \
		-e ROLENAME -e PAYER_ID  -e OUTPUT_BUCKET \
		$(IMAGENAME)

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
	$(eval IMAGE_ID := $(shell docker images $(IMAGENAME) --format "{{.ID}}" ))
endif
	$(eval AWS_ACCOUNT_ID := $(shell aws sts get-caller-identity --query Account --output text ))
	aws ecr get-login-password --region $(AWS_DEFAULT_REGION) | docker login --username AWS --password-stdin $(AWS_ACCOUNT_ID).dkr.ecr.$(AWS_DEFAULT_REGION).amazonaws.com
	docker tag $(IMAGE_ID) $(AWS_ACCOUNT_ID).dkr.ecr.$(AWS_DEFAULT_REGION).amazonaws.com/$(IMAGENAME):$(version)
	docker push $(AWS_ACCOUNT_ID).dkr.ecr.$(AWS_DEFAULT_REGION).amazonaws.com/$(IMAGENAME):$(version)

container: build push

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
	cft-deploy -m cloudformation/$(PROWLER_MANIFEST) --template-url $(PROWLER_TEMPLATE_URL) pTemplateURL=$(PROWLER_TEMPLATE_URL) pImageVersion=$(IMAGE_VERSION) --force


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


#
# Push Configs
#
push-config:
	@aws s3 cp $(CONFIG_FILE) s3://$(OUTPUT_BUCKET)/config.yaml
	@aws s3 cp $(CHECKS_FILE) s3://$(OUTPUT_BUCKET)/checks.json

fetch-config:
	@aws s3 cp s3://$(OUTPUT_BUCKET)/config.yaml $(CONFIG_FILE)
	@aws s3 cp s3://$(OUTPUT_BUCKET)/checks.json $(CHECKS_FILE)


clean:
	cd lambda && $(MAKE) clean

# EOF