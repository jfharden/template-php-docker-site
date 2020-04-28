FROM php:5.6-apache

LABEL maintainer="jfharden@gmail.com"

RUN apt-get update && apt-get install -y \
    libpq-dev \
  && apt-get autoremove --purge -y \
  && apt-get clean \
  && docker-php-ext-install pgsql \
  && mkdir /secrets/ \
  && chown root:www-data /secrets \
  && chmod 550 /secrets \
  && mkdir /sessions/ \
  && chown www-data:www-data /sessions/ \
  && chmod 700 /sessions/ \
  && sed -i 's/^ServerSignature On/ServerSignature Off/' /etc/apache2/conf-enabled/security.conf \
  && sed -i 's/^ServerTokens OS/ServerTokens Prod/' /etc/apache2/conf-enabled/security.conf

COPY docker-config/date.timezone.ini /usr/local/etc/php/conf.d/
COPY docker-config/hardening.ini /usr/local/etc/php/conf.d/99-hardening.ini
COPY --chown=www-data:www-data src/ /var/www/html/

COPY --chown=root:www-data docker-config/rds-combined-ca-bundle.pem /secrets/rds-combined-ca-bundle.pem
COPY docker-config/entrypoint.sh /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["apache2-foreground"]
