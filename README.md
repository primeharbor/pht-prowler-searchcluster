# prowler-searchcluster

Manage Prowler & Security Hub findings in OpenSearch

## Deploying Prowler

1. Create a config file named `config.FOO` with your specific settings.
```
export DEPLOY_BUCKET=fooli-deploy
export DEPLOY_PREFIX=prowler
export CHECKS_FILE=fooli-checks.json
export CONFIG_FILE=fooli-config.yaml
export PROWLER_MANIFEST=Fooli-Prowler-Manifest.yaml
export IMAGE_VERSION=20230805-1201

# Used by a local run
export ROLENAME=fooli-audit
export PAYER_ID=123456789012
export OUTPUT_BUCKET=fooli-prowler
```

2. Create Manifest. `cft-generate-manifest -m Fooli-Prowler-Manifest.yaml -t cloudformation/Prowler-Template.yaml`
3. Edit Manifest.
    1. If you're not using opensearch, you can just set the `pDomainEndpoint` to the value of NONE
3. Make the ECR Repo: `make env=FOO repo`
4. Push the container:  `make env=FOO push` (you need docker running)
    1. Update the Config file to set the correct `IMAGE_VERSION`
5. Deploy: `make env=FOO prowler-deploy`


## Deploying OpenSearch

1. Deploy the template found in [cloudformation/OpenSearch-Template.yaml](cloudformation/OpenSearch-Template.yaml)
2. Get the Admin Password from Secrets Manager
2. Enable [IAM Mapping](https://docs.aws.amazon.com/opensearch-service/latest/developerguide/fgac.html#fgac-more-masters). This is needed to leveage IAM roles to access the OpenSearch.
  1. `./scripts/enable_iam_roles.sh <OpenSearch-StackName> <Prowler-StackName>`


