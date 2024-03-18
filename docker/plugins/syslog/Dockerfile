# vim: syntax=dockerfile
FROM nexus.privatehost.com:8442/python:3.8-slim

#ENV PYTHONUNBUFFERED 1
#ENV PIP_DISABLE_PIP_VERSION_CHECK=1
#ENV PIP_NO_CACHE_DIR=1

ARG VERSION="1.0.0"
ARG RELEASE="stable"
ARG VCS_REF=""
ARG BUILD_DATE=now

RUN update-ca-certificates
ENV CA_REQUESTS_BUNDLE /etc/ssl/certs/ca-certificates.crt
ENV PIP_CERT /etc/ssl/certs/ca-certificates.crt

LABEL org.label-schema.build-date=$BUILD_DATE \
      org.label-schema.url="https://snoozeweb.net" \
      org.label-schema.vcs-url="https://github.com/dataemon/snooze_plugins.git#subdirectory=input/syslog" \
      org.label-schema.vcs-ref=$RELEASE \
      org.label-schema.version=${VERSION}-${RELEASE} \
      org.label-schema.schema-version="1.0.0-rc.1"

# SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# hadolint ignore=DL3008
#RUN sed -i 's/https/http/g' /etc/apk/repositories
RUN apt-get update && \
    apt-get install -y \
    curl \
    git

RUN pip install --no-cache-dir pip==21.0.1 virtualenv==20.4.4

RUN mkdir -p /opt/snooze /etc/snooze/ && \
    python3 -m venv /opt/snooze && \
    /opt/snooze/bin/pip install python-dateutil==2.8.2

# install the snooze_client
RUN /opt/snooze/bin/pip install --no-cache-dir git+https://github.com/dataemon/snooze_client.git

# install the syslog plugin
RUN /opt/snooze/bin/pip install --no-cache-dir git+https://github.com/dataemon/snooze_plugins.git#subdirectory=input/syslog


RUN chgrp -R 0 /opt/snooze && \
    chmod -R g=u /opt/snooze 

USER root

COPY docker-entrypoint.sh /opt/snooze/
COPY *.yaml /etc/snooze/

WORKDIR /opt/snooze/bin/

ENTRYPOINT ["/opt/snooze/docker-entrypoint.sh"]

EXPOSE 1514/tcp
EXPOSE 1514/udp
