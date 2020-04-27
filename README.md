# Template repo for php docker services

## Setup new project

1. Copy this entire project into your new project directory (or copy the template github repo)
2. In `/test` initialise the go module (written for go 1.13) `go mod init github.com/youruser/yourproject` and check
   the tests work as-is `go test -v`
3. Replace everywhere that says `php-service` (in `docker-compose.yaml`, `Dockerfile`, 
   `scripts/create-production-docker-compose.sh`) with the name of your project
4. Put your code in src/ directory (along with the already existing .htaccess, replace the index.php file there
   already)
5. Edit the SSM\_PREFIX env var in /scripts/create-production-docker-compose.sh
6. Put an sql, or sql.gz file in `/db-seeds/seeds.sql.gz` which has the seeds for your db test data (incl. structure)

## What you get

1. Inside the docker container
    1. Hardened PHP service running php 5.6 and configured for a UTC timezone (edit `/docker-config/date.timezone.ini`
       if you wish to have a different server timezone) running with apache
    2. By default the service will be protected with an htaccess file (populated from HTPASSWD\_FILE env var)
    3. A /secrets directory, outside the apache web directory, accessible by your code to store things like
       database config etc (add more things as you wish in the Dockerfile)
    4. A script `/docker-config/entrypoint.sh` which does the following:
        1. Loads some SSM params (see below) and puts them into a config file inside the container `/secrets/config.php`
           which has the following things set:
            1. $_CONF['db_name'] set to env var DB_NAME
            2. $_CONF['db_host'] set to env var DB_HOST
            3. $_CONF['db_user'] set to env var DB_USER
            4. $_CONF['db_pass'] set to env var DB_PASS
            5. $_CONF['sslmode'] set to env var SSLMODE
            6. $_CONF['sslrootcert'] set to env var SSLROOTCERT
        2. Creates an htpasswd file in /secrets/htpasswd from the HTPASSWD_FILE env var
        3. Makes a /sessions directory which php is configured to use for storing session.
        4. Calls the entrypoint of the php container with whatever command you chose (it defaults to running apache)
        5. Unsets all the env vars at the end so they can't be seen anymore
    5. The RDS SSL combined ca bundle inside the container at `/secrets/rds-combined-ca-bundle.pem` giving you verified
       SSL connections to AWS RDS instances
3. Docker-compose file giving you 
    1. A postgres 9.6.11 dependency with a persistent data volume which is seeded from `/db-seeds/*.sql.gz`
    2. A default user (testdb), database (testdb), and password for postgres
    3. Your src/ directory mounted into /var/www/html so it will update live if you change any files while the
       container is running
4. A script to generate a docker-compose file (which is gitignored) which will have your production
   credentials in (loaded from SSM, so you will need to run with a valid AWS\_PROFILE)
5. Terratest tests which will
    1. Build and launch the docker file
    2. Run a few tests to check for hardening, htpasswd basic auth, and that index.php can be retrieved.
    3. Are written with stages (which can be individually skipped by setting env vars SKIP\_\<stage\>,
       e.g. SKIP_build=true):
        1. build (docker-compose build)
        2. launch (docker-compose up
        3. verify (run the tests)
        4. destroy (docker-compose down (will also remove the postgres volume used in the tests))

## Requirements

## To build the project

1. go 1.13+ (for the tests)
2. docker-compose (any version which supports compose templates 3+, written and tested with 1.25)

## To run the docker container without the docker-compose file

1. Env vars:
    1. DB_HOST: Host name of the postgres instance to connect to
    2. DB_NAME: Name of the database inside the postgres host
    3. DB_USER: Username to auth for postgres
    4. DB_PASS: Password to auth for postgres
    5. SSLMODE: PHP postgres SSL mode (verify-full suggested for production)
    6. SSLROOTCERT: The path to the SSL cert for verifying the SSL connection to the server (for AWS RDS (which is
       included in the docker container for you) set this to `/secrets/rds-combined-ca-bundle.pem`)
    7. HTPASSWD_FILE: The content to put into the htpasswd file
