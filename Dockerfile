FROM python:3.9

LABEL maintainer="https://github.com/primeharbor/prowler-elastistats"

# Create nonroot user
RUN mkdir -p /home/prowler && \
    echo 'prowler:x:1000:1000:prowler:/home/prowler:' > /etc/passwd && \
    echo 'prowler:x:1000:' > /etc/group && \
    chown -R prowler:prowler /home/prowler
USER prowler

# Copy necessary files
WORKDIR /home/prowler
ENV HOME='/home/prowler'
ENV PATH="$HOME/.local/bin:$PATH"
RUN pip install --no-cache-dir --upgrade pip
RUN git clone https://github.com/primeharbor/prowler.git
RUN cd prowler ; pip install --no-cache-dir .

COPY scripts/scan_organization.sh /home/prowler
CMD /home/prowler/scan_organization.sh