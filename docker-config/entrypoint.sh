#!/bin/bash

set -e

echo "Writing PHP config file"

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

if [ -n "$HTPASSWD_FILE" ]; then
  echo "HTPASSWD_FILE provided, setting up basic auth"
  cat > /var/www/html/.htaccess <<-EOF
    AuthType Basic
    AuthName "Authorisation Required"
    AuthUserFile "/secrets/htpasswd"
    require valid-user
EOF
  chown www-data:www-data /var/www/html/.htaccess
  chmod 440 /var/www/html/.htaccess

  echo "$HTPASSWD_FILE" > /secrets/htpasswd
  chmod 440 /secrets/htpasswd
  chown root:www-data /secrets/htpasswd
  echo "Created /secrets/htpasswd"
else
  echo "HTPASSWD_FILE not provided, basic auth disabled"
fi

if [ "$OPENID_ENABLED" == "true" ]; then
  echo "OpenID has been requested, writing apache config"

  cat > /etc/apache2/conf-available/openid.conf <<-EOF
    # SEE https://medium.com/@robert.broeckelmann/openid-connect-authorization-code-flow-with-aws-cognito-246997abd11a
    
    # MetaData URL for AWS cognito is:
    #   https://cognito-idp.<REGION>.amazonaws.com/<USER_POOL_ID>/.well-known/openid-configuration
    
    # TODO From ENV (all 3)
    OIDCProviderMetadataURL $OPENID_METADATA_URL
    OIDCClientID $OPENID_CLIENT_ID
    OIDCClientSecret $OPENID_SECRET
    
    # OIDCRedirectURI is a vanity URL that must point to a path protected by this module but must NOT point to any content
    OIDCRedirectURI $OPENID_REDIRECT_URL
    # TODO From env/random See https://github.com/zmartzone/mod_auth_openidc/blob/master/auth_openidc.conf#L16 for what this is
    OIDCCryptoPassphrase $OPENID_CRYPTO_PASSPHRASE

    
    <LocationMatch "^/(?!loggedout.html)">
       AuthType openid-connect
       Require valid-user
    </LocationMatch>

EOF

  # Some open connect providers aren't giving the logout uri in the metadata (looking at you AWS Cognito!) so if it's
  # specified we need to include it in the OpenID config
  if [ -n "$OPENID_END_SESSION_ENDPOINT" ]; then
    echo "    OIDCProviderEndSessionEndpoint $OPENID_END_SESSION_ENDPOINT" >> /etc/apache2/conf-available/openid.conf
  fi

  chmod 400 /etc/apache2/conf-available/openid.conf
  a2enconf openid
else
  echo "OpenID has not been enabled"
fi

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
unset OPENID_ENABLED
unset OPENID_END_SESSION_ENDPOINT
unset OPENID_METADATA_URL
unset OPENID_CLIENT_ID
unset OPENID_SECRET
unset OPENID_REDIRECT_URL
unset OPENID_CRYPTO_PASSPHRASE

echo "Custom entrypoint setup complete, running docker-php-entrypoint"

exec "/usr/local/bin/docker-php-entrypoint" "$@"
