FROM python:2.7-stretch

MAINTAINER DomExpire <contact@domexpire.fr>

RUN apt-get update > /dev/null && apt-get install -y --no-install-recommends > /dev/null \
    python-twisted exim4-daemon-light mailutils

RUN pip install pyOpenSSL

COPY python /app

COPY docker/run.sh /usr/local/bin

WORKDIR /app

ENTRYPOINT /usr/local/bin/run.sh
