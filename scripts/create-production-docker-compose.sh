#!/bin/bash

set -e

SSM_PREFIX=/php-service

echo "Loading secrets from SSM"

DB_HOST=`aws ssm get-parameter --region us-east-1 --name $SSM_PREFIX/db/host --with-decryption --output text --query "Parameter.Value"`
if [ $? -ne 0 ]; then
  echo "Failed to lookup DB_HOST in SSM key $SSM_PREFIX/db/host"
  exit 3
fi

echo "Loaded DB Host: $SSM_PREFIX/db/host"

DB_NAME=`aws ssm get-parameter --region us-east-1 --name $SSM_PREFIX/db/name --with-decryption --output text --query "Parameter.Value"`
if [ $? -ne 0 ]; then
  echo "Failed to lookup DB_NAME in SSM key $SSM_PREFIX/db/name"
  exit 3
fi

echo "Loaded DB Name: $SSM_PREFIX/db/name"

DB_USER=`aws ssm get-parameter --region us-east-1 --name $SSM_PREFIX/db/ro-user --with-decryption --output text --query "Parameter.Value"`
if [ $? -ne 0 ]; then
  echo "Failed to lookup DB_USER in SSM key $SSM_PREFIX/db/ro-user"
  exit 3
fi

echo "Loaded DB User: $SSM_PREFIX/db/ro-user"

DB_PASS=`aws ssm get-parameter --region us-east-1 --name $SSM_PREFIX/db/ro-password --with-decryption --output text --query "Parameter.Value"`
if [ $? -ne 0 ]; then
  echo "Failed to lookup DB_PASS key in SSM key $SSM_PREFIX/db/ro-password"
  exit 3
fi

echo "Loaded DB Host: $SSM_PREFIX/db/ro-password"

HTPASSWD_FILE=`
  aws ssm get-parameter --region us-east-1 --name $SSM_PREFIX/users/htpasswd --with-decryption --output text --query "Parameter.Value" | 
    sed -E 's/\\$/$$/g' | 
    sed -E 's/^/        /'`
if [ $? -ne 0 ]; then
  echo "Failed to lookup HTPASSWD key in SSM key $SSM_PREFIX/users/htpasswd"
  exit 3
fi

echo "Loaded htpasswd file: $SSM_PREFIX/users/htpasswd"


echo "version: '3'
services:
  php-service:
    build: .
    ports:
      - \"80:80\"
    environment:
      DB_HOST: $DB_HOST
      DB_NAME: $DB_NAME
      DB_USER: $DB_USER
      DB_PASS: $DB_PASS
      SSLMODE: verify-full
      SSLROOTCERT: /secrets/rds-combined-ca-bundle.pem
      HTPASSWD_FILE: |-
$HTPASSWD_FILE
" > docker-compose.production.yaml

echo "Created docker-compose.production.yaml"
