FROM envoyproxy/envoy:latest AS envoy

RUN apt-get update && apt-get install -y python3-pip
RUN apt-get install -y software-properties-common
RUN add-apt-repository -y ppa:certbot/certbot && apt-get update && apt-get install -y python-certbot-apache

RUN apt-get install -y zip unzip curl jq
RUN pip3 install --upgrade pip
RUN pip3 install certbot_dns_route53==0.22.2
RUN pip3 install awscli configparser

ADD bin /usr/local/bin
RUN chmod +x /usr/local/bin/certsync.sh
RUN chmod +x /usr/local/bin/certbot.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/switchboard.py

CMD ["/usr/local/bin/docker-entrypoint.sh"]
