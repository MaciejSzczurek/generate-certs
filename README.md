# Generate Certs

A simple wrapper script for certbot, which allows you to easily obtain SSL certificates and restart the nginx server or
install DNS TLSA type entries for the mail server.

In addition, the repository includes a quick tool for regenerating authentication keys to OVH.

## Installation

You can run the scripts directly from the project files or from the docker image. To prepare the docker image, type at
the command line:

```bash
docker build --pull -t maciejszczurek/generate-certs .
```

Then the script can be run through the command:

```bash
docker run -it --rm maciejszczurek/generate-certs generate-certs
```

## Usage

```
usage: generate-certs [--days DAYS] [--test-cert TEST_CERT] [--restart-nginx RESTART_NGINX]
                      [--reset-files RESET_FILES] [--mailcow-path MAILCOW_PATH] [--mailcow-domain MAILCOW_DOMAIN]
                      [--mailcow-subdomain MAILCOW_SUBDOMAIN] [--keycloak-path KEYCLOAK_PATH]
                      [--regenerate-tlsa REGENERATE_TLSA] [--without-rsa WITHOUT_RSA] [-h]
                      options domains [domains ...]

positional arguments:
  options               dns-lexicon options file
  domains               List of domains to obtain a certificate for

options:
  --days DAYS           Number of days before a new certificate will be generated
  --test-cert TEST_CERT
                        Obtain a test certificate from a staging server
  --restart-nginx RESTART_NGINX
                        Restart nginx after obtaining certificate
  --reset-files RESET_FILES
                        Recover certificate files from backup
  --lemp-path LEMP_PATH
                        Location for Docker Lemp
  --nginx-container NGINX_CONTAINER
                        Nginx container name
  --mailcow-path MAILCOW_PATH
                        Location of mailcow files
  --mailcow-domain MAILCOW_DOMAIN
                        The main domain used in mailcow.
  --mailcow-subdomain MAILCOW_SUBDOMAIN
                        The main subdomain used in mailcow
  --keycloak-path KEYCLOAK_PATH
                        Location of keycloak path
  --regenerate-tlsa REGENERATE_TLSA
                        Generate and add certificate keys to the dns server
  --without-rsa WITHOUT_RSA
                        Don't create rsa certificates
  -h, --help            show this help message and exit
```

## Contributing

Pull requests are always welcome.

## License

[Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0)
