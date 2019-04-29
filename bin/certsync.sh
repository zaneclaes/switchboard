#!/bin/bash
sl="/etc/letsencrypt"
fnz="${sl}.zip"
s3b=${S3_BUCKET}
s3z="s3://${s3b}/letsencrypt.zip"

if [[ -z "$s3b" ]]; then
  # echo "[Warn] no S3 bucket for letsencrypt"
  exit 0
fi

link_cert() {
  install="$1"
  fn="$2"
  ap=$(find "$sl/archive/${install}" -name "${fn}*.pem" -type f)
  if [[ ! -z "$ap" ]]; then
    lp="$sl/live/${install}/${fn}.pem"
    # echo "link $fn at $lp"
    rm -rf $lp
    ln -s "$ap" "$lp"
  fi
}

if [[ $1 = "backup" ]]; then
  echo "Backing up $sl to $s3z..."
  if [[ -f "/var/log/letsencrypt/letsencrypt.log" ]]; then
    cp -f "/var/log/letsencrypt/letsencrypt.log" "$sl/letsencrypt.log"
  fi
  cd "$sl"
  zip -r -q --exclude="*.DS_Store*" "$fnz" .
  aws s3 cp "$fnz" "$s3z" --sse AES256
elif [[ $1 = "restore" ]]; then
  if [[ -d "$sl/live" ]]; then
    # echo "$sl/live is already present."
    exit 0
  fi
  # echo "Restoring $fnz from $s3z..."
  mkdir -p "$sl"
  aws s3 cp "$s3z" "$fnz"
  unzip -q -o "$fnz" -d "$sl"

  find "$sl/live" -maxdepth 1 -mindepth 1 -type d | while read dir
  do
    install=$(basename "$dir")
    link_cert "$install" "chain"
    link_cert "$install" "cert"
    link_cert "$install" "fullchain"
    link_cert "$install" "privkey"
  done
else
  echo "Unknown mode: $1"
  exit 1
fi
