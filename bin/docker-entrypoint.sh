#!/bin/bash
sleep 3 # Give kube2iam a second.

echo "configuring envoy..."
python3 /usr/local/bin/switchboard.py # generates envoy.yaml
if [[ "${loglevel}" = "debug" ]]; then
  echo "Generated Envoy YAML:"
  echo "$(cat envoy.yaml)"
fi
cp envoy.yaml /etc/envoy.yaml

echo "starting envoy..."
/usr/local/bin/envoy -l ${loglevel:-info} --log-path ${logpath:-/dev/stdout} -c /etc/envoy.yaml &
wait
