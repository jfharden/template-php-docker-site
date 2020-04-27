#!/bin/bash

set -e

echo "Writing config file"

echo "<?php
	\$_CONF['db_name'] = \"$DB_NAME\";
	\$_CONF['db_host'] = \"$DB_HOST\";
	\$_CONF['db_user'] = \"$DB_USER\";
	\$_CONF['db_pass'] = \"$DB_PASS\";
  \$_CONF['sslmode'] = \"$SSLMODE\";
  \$_CONF['sslrootcert'] = \"$SSLROOTCERT\";
?>" > /secrets/config.php
chmod 440 /secrets/config.php
chown root:www-data /secrets/config.php
echo "Created /secrets/config.php"

echo "$HTPASSWD_FILE" > /secrets/htpasswd
chmod 440 /secrets/htpasswd
chown root:www-data /secrets/htpasswd
echo "Created /secrets/htpasswd"

echo "Changing permissions of /sessions/"
chown www-data:www-data /sessions/
chmod 770 /sessions/

echo "Unsetting env vars"
unset DB_NAME
unset DB_HOST
unset DB_USER
unset DB_PASS
unset SSLMODE
unset SSLROOTCERT
unset HTPASSWD_FILE

echo "Custom entrypoint setup complete, running docker-php-entrypoint"

exec "/usr/local/bin/docker-php-entrypoint" "$@"
