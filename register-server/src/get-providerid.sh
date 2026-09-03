#!/bin/bash
# SPDX-FileCopyrightText: Roy Kaufman <rkaufman@redhat.com>
#
# SPDX-License-Identifier: MIT


set -euo pipefail


UUID="<YOUR_UUID>"
BIND_URL="<YOUR_BIND_SERVER_URL>"
# PEM of the register-server CA, or empty when the server is plain HTTP.
CA_CERT="<YOUR_CA_CERT>"

IMDS_URL="http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01"

# Azure Instance Metadata Service returns the ARM resource ID of this VM.
PROVIDER_ID="azure://$(curl -fsS -H 'Metadata: true' "$IMDS_URL" | jq -r .resourceId)"


curl_args=(-fsS -X PUT -H 'Content-Type: application/json'
	--retry 5 --retry-connrefused --retry-delay 5)

# Pin the register-server CA so curl can verify the HTTPS certificate.
if [ -n "$CA_CERT" ]; then
	ca_file="$(mktemp)"
	trap 'rm -f "$ca_file"' EXIT
	printf '%s' "$CA_CERT" >"$ca_file"
	curl_args+=(--cacert "$ca_file")
fi

curl "${curl_args[@]}" \
	-d "$(jq -nc --arg uuid "$UUID" --arg providerID "$PROVIDER_ID" '{uuid: $uuid, providerID: $providerID}')" \
	"$BIND_URL"

echo "UUID=$UUID providerID=$PROVIDER_ID"
