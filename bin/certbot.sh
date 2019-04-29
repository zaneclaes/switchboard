#!/bin/bash
le_dir="/etc/letsencrypt"
domain=${1}
email=${2:-zane@experium.online}

fn_renew="${le_dir}/renewal/${domain}.conf"
if [[ ! -f "$fn_renew" ]]; then
  echo "[Balancer] no renewal for $domain :: $(ls ${le_dir}/renewal)"
  echo "[Balancer] Fetching $domain for $email..."
  certbot certonly -d "*.${domain}" -d $domain -m $email --dns-route53 \
    --server https://acme-v02.api.letsencrypt.org/directory \
    --agree-tos --non-interactive
else
  echo "[Balancer] Renewing $domain for $email via $fn_renew..."
  certbot renew --dns-route53 --non-interactive
  #  --post-hook "sudo service nginx reload"
fi
