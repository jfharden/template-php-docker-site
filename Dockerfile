# Build stage to build the mod_auth_openidc apache module (the version in Debian stretch is too old)
FROM php:5.6-apache AS mod_builder

RUN apt-get update && apt-get install -y \
      apache2-dev  \
      libcjose-dev \
      libcurl4-openssl-dev \
      libjansson-dev \
      libpcre3-dev \
      libssl-dev \
      pkg-config \
      git \
  && apt-get clean

RUN mkdir /mod_auth_src \
  && cd /mod_auth_src \
  && git clone --branch v2.4.2.1 --depth 1 https://github.com/zmartzone/mod_auth_openidc

WORKDIR /mod_auth_src/mod_auth_openidc

RUN ./autogen.sh \
  && ./configure \
  && make \
  && make install

FROM php:5.6-apache

LABEL maintainer="jfharden@gmail.com"

# The following libraries installed as dependencies for:
#   mod_auth_openidc:
#     libcjose0 
#     libjansson4 
#     libpcre3 
#     libpq-dev 
#     libssl1.1 
#   pgsql php extension:
#     libpq-dev
RUN apt-get update && apt-get install -y \
    libcjose0 \
    libjansson4 \
    libpcre3 \
    libpq-dev \
    libssl1.1 \
  && apt-get autoremove --purge -y \
  && apt-get clean \
  && docker-php-ext-install pgsql \
  && mkdir /secrets/ \
  && chown root:www-data /secrets \
  && chmod 550 /secrets \
  && mkdir /sessions/ \
  && chown www-data:www-data /sessions/ \
  && chmod 700 /sessions/ \
  && sed -i 's/^ServerSignature On/ServerSignature Off/' /etc/apache2/conf-available/security.conf \
  && sed -i 's/^ServerTokens OS/ServerTokens Prod/' /etc/apache2/conf-available/security.conf \
  && mkdir -p /opt/lib/apache2/modules \
  && chmod 755 /opt/lib/apache2/modules \
  && echo "LoadModule auth_openidc_module /opt/lib/apache2/modules/mod_auth_openidc.so" > /etc/apache2/mods-available/auth_openidc.load

COPY --from=mod_builder /usr/lib/apache2/modules/mod_auth_openidc.so /opt/lib/apache2/modules/mod_auth_openidc.so

RUN chmod 644 /opt/lib/apache2/modules/mod_auth_openidc.so \
  && a2enmod auth_openidc

COPY config/docker/date.timezone.ini /usr/local/etc/php/conf.d/
COPY config/docker/hardening.ini /usr/local/etc/php/conf.d/99-hardening.ini
COPY config/docker/entrypoint.sh /entrypoint.sh

COPY --chown=root:www-data config/docker/rds-combined-ca-bundle.pem /secrets/rds-combined-ca-bundle.pem
COPY --chown=www-data:www-data src/ /var/www/html/

ENTRYPOINT ["/entrypoint.sh"]
CMD ["apache2-foreground"]
