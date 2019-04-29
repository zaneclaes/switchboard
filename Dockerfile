FROM envoyproxy/envoy:latest AS envoy

RUN apt-get update && apt-get install -y software-properties-common
RUN apt-get install -y zip unzip curl
RUN add-apt-repository -y ppa:certbot/certbot && apt-get update && apt-get install -y python-certbot-apache
RUN add-apt-repository -y ppa:deadsnakes/ppa && apt-get update && apt-get install -y python3.7

RUN curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py && \
  python3.7 get-pip.py && \
  rm -rf get-pip.py
RUN pip3 install certbot_dns_route53 awscli configparser cffi

ADD bin /usr/local/bin

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["envoy", "-c", "envoy.yaml"]
