# Copyright 2021-2023 Chris Farris <chrisf@primeharbor.com>
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

FROM python:3.11

ARG PROWLER_VERSION
LABEL maintainer="https://github.com/primeharbor/pht-prowler-searchcluster"

# Create nonroot user
RUN mkdir -p /home/prowler && \
    echo 'prowler:x:1000:1000:prowler:/home/prowler:' > /etc/passwd && \
    echo 'prowler:x:1000:' > /etc/group && \
    chown -R prowler:prowler /home/prowler

COPY scripts/scan_organization.sh /home/prowler/scan_organization.sh
COPY scripts/scan_account.sh /home/prowler/scan_account.sh
COPY scripts/enable_prowler_securityhub_integration.py /home/prowler/enable_prowler_securityhub_integration.py
RUN chown prowler /home/prowler/scan_organization.sh /home/prowler/enable_prowler_securityhub_integration.py /home/prowler/scan_account.sh
RUN chmod 755 /home/prowler/scan_organization.sh /home/prowler/enable_prowler_securityhub_integration.py /home/prowler/scan_account.sh

COPY scripts/install_prowler.sh /home/prowler/install_prowler.sh
RUN chown prowler /home/prowler/install_prowler.sh
RUN chmod 755 /home/prowler/install_prowler.sh

# Install prowler as prowler
USER prowler
WORKDIR /home/prowler
ENV HOME='/home/prowler'
ENV PATH="$HOME/.local/bin:$PATH"
RUN pip install --no-cache-dir --upgrade pip
RUN /home/prowler/install_prowler.sh ${PROWLER_VERSION}
RUN pip install awscli

CMD /home/prowler/scan_organization.sh