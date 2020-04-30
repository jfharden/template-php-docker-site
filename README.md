# Template repo for php docker services

## Setup new project

1. Copy this entire project into your new project directory (or copy the template github repo)
2. In `/test` initialise the go module (written for go 1.13) `go mod init github.com/youruser/yourproject` and check
   the tests work as-is `go test -v`
3. Replace everywhere that says `php-service` (in `docker-compose.yaml`, `Dockerfile`, 
   `scripts/create-production-docker-compose.sh`) with the name of your project
4. Put your code in src/ directory (replace the index.php and loggedout.php files there
   already)
5. Edit the SSM\_PREFIX env var in /scripts/create-production-docker-compose.sh
6. Put an sql, or sql.gz file in `/config/db-seeds/seeds.sql.gz` which has the seeds for your db test data (incl. structure)
7. If you are going to use [OpenID Connect authentication](#openid-auth) you should edit `config/docker/entrypoint.sh`
   and change the LocationMatch setting in the openid config to match whatever file you want to present to users when
   they logout. (or just update `src/loggedout.php` with your content).

## What you get

1. Inside the docker container
    1. Hardened PHP service running php 5.6 and configured for a UTC timezone (edit `/config/docker/date.timezone.ini`
       if you wish to have a different server timezone) running with apache
    2. You can choose to have no auth (don't set HTPASSWD\_FILE env var, or OPENID\_ENABLED env vars), but you can also
       enable HTTP Basic Auth by providing an htpasswd file in the HTPASSWD_FILE env var, or openid connect by setting
       the env var OPENID_ENABLED=true. If you do this you will need to provide aditional configuration.
       See [OpenID Connect authentication](#openid-auth).
    3. A /secrets directory, outside the apache web directory, accessible by your code to store things like
       database config etc (add more things as you wish in the Dockerfile)
    4. A script `/config/docker/entrypoint.sh` which does the following:
        1. Loads some SSM params (see below) and puts them into a config file inside the container `/secrets/config.php`
           which has the following things set:
            1. $_CONF['db_name'] set to env var DB\_NAME
            2. $_CONF['db_host'] set to env var DB\_HOST
            3. $_CONF['db_user'] set to env var DB\_USER
            4. $_CONF['db_pass'] set to env var DB\_PASS
            5. $_CONF['sslmode'] set to env var SSLMODE
            6. $_CONF['sslrootcert'] set to env var SSLROOTCERT
        2. Creates an htpasswd file in /secrets/htpasswd from the HTPASSWD_FILE env var, and enables basic auth if the
           HTPASSWD\_FILE env var is set.
        3. Creates an apache config for openid connect auth (using mod\_auth\_openidc) if the OPENID\_ENABLED env var
           is set to "true". (See later for discussion of other variables which need to be set for this to work).
        4. Makes a /sessions directory which php is configured to use for storing session.
        5. Calls the entrypoint of the php container with whatever command you chose (it defaults to running apache)
        6. Unsets all the env vars at the end so they can't be seen anymore
    5. The RDS SSL combined ca bundle inside the container at `/secrets/rds-combined-ca-bundle.pem` giving you verified
       SSL connections to AWS RDS instances
3. Several docker-compose files for difference scenarios. Giving you:
    1. In all docker-compose files:
        1. A postgres 9.6.11 dependency for your app with a persistent data volume which is seeded from
           `/config/db-seeds/*.sql.gz`
        2. A default user (testdb), database (testdb), and password for postgres
        3. Your src/ directory mounted into /var/www/html so it will update live if you change any files while the
           container is running. This is exposed on port 80 by default (overridable with HTTP_PORT env var).
    2. In `docker-compose.htpasswd.yaml`
        1. Only the same as the common options but 'protected' by a default HTTP Basic Auth configuration with user foo
           and password bar.
    3. In `docker-compose.openid.yaml`
        1. A keycloak server with some defaults to mean you can locally do openid authentication during testing. (The
           included default openid user is foo with password bar. The keycloak admin interface is exposed on 
           port 8080 by default (overridable with env var KEYCLOAK_PORT)
        2. A postgres 9.6.11 dependency for keycloak
        3. Your local website protected by openid authentication against the local keycloak server. There is a
           pre-configured user with name foo and password bar.
    4. In `docker-compose.cognito.example.yaml`
        1. An nginx reverse proxy providing a self-signed SSL cert and proxying to your php service (this helps with
           testing integrations like cognito which require redirecting back to an SSL endpoint), this is exposed on
           https://10.100.0.4
        2. Helpful (hopefully) example values for the OpenID configuration needed for cognito. See
           [OpenID Connect authentication](#openid-auth) for more help configuring this.
4. A script to generate a docker-compose file (which is gitignored) which will have your production
   credentials in (loaded from SSM, so you will need to run with a valid AWS\_PROFILE)
5. A couple of scripts for improting and exporting the keycloak settings (if you change them you can persist them
   by running the `scripts/keycloak-export.sh` script, this will update `config/keycloak/local_realm.json` with your
   changes.
6. An example docker-compose `docker-compose.cognito.example.yaml` file for doing local development against a cognito
   user pool
5. Terratest tests which will
    1. Build and launch the docker file
    2. Run a validations to check for hardening, htpasswd basic auth, openid auth, and that index.php can be retrieved.
    3. Are written with stages (which can be individually skipped by setting env vars SKIP\_\<stage\>,
       e.g. SKIP_build=true):
        1. build (docker-compose build)
        2. launch (docker-compose up
        3. verify (run the tests)
        4. destroy (docker-compose down (will also remove the postgres volume used in the tests))

### <a id="openid-auth">OpenID Connect authentication</a>

This has been tested against AWS Cognito with openid enabled (see [Robert Broekelmanns post on medium](https://medium.com/@robert.broeckelmann/openid-connect-authorization-code-flow-with-aws-cognito-246997abd11a)
for the guide I followed to learn about setting up Cognito user pools and app clients).

To enable OpenID auth you need to set the following env vars:

Env var | Value | Notes
--- | --- | ---
OPENID\_ENABLED | "true" | Must be the string true
OPENID\_METADATA\_URL | The well known metadata url for your provider | In cognito this is `https://cognito-idp.<REGION>.amazonaws.com/<COGNITO_USER_POOL_ID>/.well-known/openid-configuration`
OPENID\_CLIENT\_ID | The clientid for your client as specified by your open id provider |
OPENID\_SECRET | The client secret for your clientas specified by your open id provider |
OPENID\_REDIRECT\_URL | The redirect URI which your provider will return the user to in your application | This needs to be set to `https://<YOUR_DOMAIN>/redirect_uri` to match the apache module configuration
OPENID\_CRYPTO\_PASSPHRASE | The passpharse mod\_auth\_openidc will use to encrypt secrets | See the [mod\_auth\_openidc config file for more info](https://github.com/zmartzone/mod_auth_openidc/blob/master/auth_openidc.conf#L16)
OPENID\_END\_SESSION\_ENDPOINT | The logout url for your open id provider | Some providers (looking at you AWS Cognito) do not provide this from the metadata endpoint, for any provider that doesn't you will need to set this explicitly.

***Special notes about OPENID\_END\_SESSION\_ENDPOINT***

**Note:** In the following the logout\_uri parameter in the OPENID\_END\_SESSION\_ENDPOINT, the logout parameter in the
logout link on your site, and the "Sign out URL(s)" in the AWS Cognito "App Client Settings" are all _identical_.

For AWS Cognito the OPENID\_END\_SESSION\_ENDPOINT env var should be:

    https://<AMAZON_COGNITO_DOMAIN>/logout?client_id=<APP_CLIENT_ID>&logout_uri=<SIGN_OUT_URL_AS_SET_IN_COGNITO_APP_CLIENT_SETTINGS>

The logout\_uri parameter needs to be a page in your site, which is _not_ protected by openid connect (this is defaulted to `src/loggedout.php` in our config).

In your app a logout link needs to be of this format:

    https://<YOUR_DOMAIN>/redirect_uri?logout=https%3A%2F%2F127.0.0.1%2Floggedout.php

**Note:** The logout parameter has to be IDENITICAL (but URI encoded!) to the "Sign out URL(s)" you specified in the AWS Cognito "App Client Settings"


## Requirements

## To build the project

1. go 1.13+ (for the tests)
2. docker-compose (any version which supports compose templates 3+, written and tested with 1.25)

## To run the docker container without the docker-compose file

1. Env vars:
    1. DB\_HOST: Host name of the postgres instance to connect to
    2. DB\_NAME: Name of the database inside the postgres host
    3. DB\_USER: Username to auth for postgres
    4. DB\_PASS: Password to auth for postgres
    5. SSLMODE: PHP postgres SSL mode (verify-full suggested for production)
    6. SSLROOTCERT: The path to the SSL cert for verifying the SSL connection to the server (for AWS RDS (which is
       included in the docker container for you) set this to `/secrets/rds-combined-ca-bundle.pem`)
    7. To optionally enable auth either:
        1. HTPASSWD\_FILE: The content to put into the htpasswd file
        2. OPENID\_ENABLED=true - See [OpenID Connect authentication](#openid-auth)
