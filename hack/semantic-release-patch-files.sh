#!/bin/sh
set -e

NEXTVERSION=$1
for file in build/openbao/plugins/openbao-plugin-secrets-nats-*; do
  sha256sum $file > $file.sha256
done
