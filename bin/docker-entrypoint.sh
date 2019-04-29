#!/bin/bash

echo "--------------------------------------------------------"
echo "Switchboard Startup"
echo "--------------------------------------------------------"
echo "configuring envoy..."
python3.7 /usr/local/bin/switchboard.py # generates envoy.yaml
if [[ "${LOG_LEVEL}" = "debug" ]]; then
  echo "Generated Envoy YAML:"
  echo "$(cat envoy.yaml)"
fi

cmd="$@ -l ${LOG_LEVEL:-info} --log-path ${LOG_PATH:-/dev/stdout}"
echo "starting $cmd..."
echo "--------------------------------------------------------"
$cmd
