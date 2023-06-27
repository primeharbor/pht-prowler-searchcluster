# Copyright 2023 - Chris Farris (chris@primeharbor.com) - All Rights Reserved
#

ifndef env
$(error env is not set)
endif

include config.$(env)
export

IMAGENAME ?= prowler
DEPLOY_PREFIX ?= deploy-packages

# Local to this Makefile Vars
MAIN_TEMPLATE=cloudformation/ProwlerStats-Template.yaml
OUTPUT_TEMPLATE_PREFIX=ProwlerStats-Template-Transformed
OUTPUT_TEMPLATE=$(OUTPUT_TEMPLATE_PREFIX)-$(version).yaml
TEMPLATE_URL ?= https://s3.amazonaws.com/$(DEPLOY_BUCKET)/$(DEPLOY_PREFIX)/$(OUTPUT_TEMPLATE)

ifndef version
	export version := $(shell date +%Y%m%d-%H%M)
endif

build:
	docker build -t $(IMAGENAME) .

run: stop
	docker run -it -v ./prowler-output:/home/prowler/prowler-output \
		-e AWS_DEFAULT_REGION -e AWS_SECRET_ACCESS_KEY -e AWS_ACCESS_KEY_ID \
		-e ROLENAME -e PAYER_ID  -e OUTPUT_BUCKET \
		$(IMAGENAME) $(ACCOUNT_ID_TO_SCAN)

build-run: stop build run

list:
	docker images | grep $(IMAGENAME)

stop:
	$(eval ID := $(shell docker ps | grep $(IMAGENAME) | cut -d " " -f 1 ))
	@if [ ! -z $(ID) ] ; then docker kill $(ID) ; fi


repo:
	aws ecr create-repository --repository-name $(IMAGENAME)

push: build
ifndef IMAGE_ID
	$(eval IMAGE_ID := $(shell docker images $(IMAGENAME) --format "{{.ID}}" ))
endif
	$(eval AWS_ACCOUNT_ID := $(shell aws sts get-caller-identity --query Account --output text ))
	aws ecr get-login-password --region $(AWS_DEFAULT_REGION) | docker login --username AWS --password-stdin $(AWS_ACCOUNT_ID).dkr.ecr.$(AWS_DEFAULT_REGION).amazonaws.com
	docker tag $(IMAGE_ID) $(AWS_ACCOUNT_ID).dkr.ecr.$(AWS_DEFAULT_REGION).amazonaws.com/$(IMAGENAME):$(version)
	docker push $(AWS_ACCOUNT_ID).dkr.ecr.$(AWS_DEFAULT_REGION).amazonaws.com/$(IMAGENAME):$(version)


deps:
	cd lambda && $(MAKE) deps

package: deps
	@aws cloudformation package --template-file $(MAIN_TEMPLATE) --s3-bucket $(DEPLOY_BUCKET) --s3-prefix $(DEPLOY_PREFIX)/transform --output-template-file cloudformation/$(OUTPUT_TEMPLATE)  --metadata build_ver=$(version)
	@aws s3 cp cloudformation/$(OUTPUT_TEMPLATE) s3://$(DEPLOY_BUCKET)/$(DEPLOY_PREFIX)/
	rm cloudformation/$(OUTPUT_TEMPLATE)

cft-deploy: package
ifndef MANIFEST
	$(error MANIFEST is not set)
endif
	cft-deploy -m cloudformation/$(MANIFEST) --template-url $(TEMPLATE_URL) pTemplateURL=$(TEMPLATE_URL) pImageVersion=$(IMAGE_VERSION) --force