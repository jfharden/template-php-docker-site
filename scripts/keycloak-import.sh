#!/bin/bash

docker-compose exec keycloak /opt/jboss/keycloak/bin/standalone.sh \
  -Djboss.socket.binding.port-offset=100 \
  -Dkeycloak.migration.action=import \
  -Dkeycloak.migration.provider=singleFile \
  -Dkeycloak.migration.strategy=OVERWRITE_EXISTING \
  -Dkeycloak.migration.file=/keycloak-config/local_realm.json
