FROM python:3.9

LABEL maintainer="https://github.com/primeharbor/prowler-elastistats"

# Create nonroot user
RUN mkdir -p /home/prowler && \
    echo 'prowler:x:1000:1000:prowler:/home/prowler:' > /etc/passwd && \
    echo 'prowler:x:1000:' > /etc/group && \
    chown -R prowler:prowler /home/prowler

COPY scripts/scan_organization.sh /home/prowler/scan_organization.sh
RUN chown prowler /home/prowler/scan_organization.sh
RUN chmod 755 /home/prowler/scan_organization.sh

# Install prowler as prowler
USER prowler
WORKDIR /home/prowler
ENV HOME='/home/prowler'
ENV PATH="$HOME/.local/bin:$PATH"
RUN pip install --no-cache-dir --upgrade pip
RUN pip install awscli
RUN git clone https://github.com/primeharbor/prowler.git
RUN cd prowler ; pip install --no-cache-dir .

CMD /home/prowler/scan_organization.sh