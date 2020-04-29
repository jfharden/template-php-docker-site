#!/bin/sh

set -e

CERT_DIR=/etc/ssl/self-signed-certs
SELF_SIGNED_KEY=$CERT_DIR/nginx-selfsigned.key 
SELF_SIGNED_CERT=$CERT_DIR/nginx-selfsigned.crt

if [ ! -f $SELF_SIGNED_KEY ] || [ ! -f $SELF_SIGNED_CERT ]; then
  echo "Self signed SSL certs not yet generated, creating"
  echo "Installing open ssl"
  apk add openssl

  echo "Generating ssl certs"
  openssl req -x509 -nodes -days 365 \
    -subj "/C=CA/ST=QC/O=Company, Inc./CN=mydomain.com" -addext "subjectAltName=DNS:mydomain.com" \
    -newkey rsa:2048 -keyout $SELF_SIGNED_KEY \
    -out $SELF_SIGNED_CERT

  echo "Removing openssl"
  apk del openssl
fi

exec nginx -g 'daemon off;'
