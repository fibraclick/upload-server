#!/usr/bin/env bash
expires=$1
path=$2
key="dev"
echo -n "$expires$path" | openssl sha256 -hmac $key | awk '{print $2}'
