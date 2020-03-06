# https://github.com/jbarratt/envoy_ratelimit_example
# https://serialized.net/2019/05/envoy-ratelimits/
FROM golang:latest as builder
COPY ./ext-authz /ext-authz
WORKDIR /ext-authz
ENV GO111MODULE=on
RUN go get
RUN CGO_ENABLED=0 GOOOS=linux go build -o ext-authz

FROM prom/statsd-exporter:latest AS statsd

FROM envoyproxy/envoy:latest AS envoy

RUN apt-get update && apt-get install -y software-properties-common
RUN apt-get install -y zip unzip curl
RUN add-apt-repository -y ppa:deadsnakes/ppa && apt-get update && apt-get install -y python3.7
# RUN add-apt-repository -y ppa:certbot/certbot && apt-get update && apt-get install -y python-certbot-apache

RUN curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py && \
  python3.7 get-pip.py && \
  rm -rf get-pip.py
RUN pip3 install certbot_dns_route53 awscli configparser cffi

ADD bin /usr/local/bin
COPY --from=builder /ext-authz /usr/local/bin
COPY --from=statsd /bin/statsd_exporter /bin/statsd_exporter

RUN mkdir -p /etc/letsencrypt

MAINTAINER Zane Claes <zane@technicallywizardry.com>
ENTRYPOINT ["/usr/local/bin/switchboard.py"]
