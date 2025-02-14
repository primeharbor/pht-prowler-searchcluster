# Copyright 2021 Chris Farris <chrisf@primeharbor.com>
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

# Static, not sure if needed??
PYTHON=python3
PIP=pip3

FILES =	import_findings.py process_finding_file.py

DEPENDENCIES=elasticsearch requests_aws4auth bin certifi idna charset_normalizer six.py urllib3 elastic_transport requests dateutil opensearchpy cachetools docs google google_auth_oauthlib gspread oauthlib pyasn1 pyasn1_modules requests_oauthlib rsa scripts strenum apiclient googleapiclient google_auth_httplib2.py proto httplib2 uritemplate pyparsing

clean:
	rm -rf __pycache__ *.zip *.dist-info *.egg-info $(DEPENDENCIES)

# # Create the package Zip. Assumes all tests were done
zipfile:  $(FILES)
	zip -r $(LAMBDA_PACKAGE) $^ $(DEPENDENCIES)

deps:
	$(PIP) install -r requirements.txt -t . --upgrade

pep8: $(FILES)
	pycodestyle $^
