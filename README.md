# SAMLProvider
This repository contains a Caddy module which implements the SAML protocol to secure backend services in a containerised setup.

There are 3 images build from this project
1. kvalitetsit/gosamlserviceprovider, which contains the SAML caddy module
1. kvalitetsit/caddysamlprovider, which contains a version of Caddy with the SAML module deployed
1. kvalitetsit/caddysamltemplates, which contains Caddy configuration templates for SAML

## Configuration
Caddy including the SAML module are configured in the Caddy json configuraion:
* [V2: Config from Scratch](https://github.com/caddyserver/caddy/wiki/v2:-Config-from-Scratch)
* [Caddy config](https://caddyserver.com/docs/json/)

To make configuration easier a configuration template is implemented, 
which can be used to configure Caddy using environment variables.
The kvalitetsit/caddysamltemplates image can be configured using the following variables


Variable  | Description | Default |
------------ | ----------- | -------- |
TEMPLATE_FILE | The json template to use, currently only one is available | //caddyfiletemplates/Caddyfile-saml |
CADDYFILE | The output destination where the compiled caddy configuration is saved | //caddy/config.json |
SAML_CLIENT_LOGLEVEL | The loglevel used in Caddy | info | 
LISTEN_PORT                 | The HTTP port that the Caddy proxy is bound to | -  |
MONGO_HOST                  | Hostname for the MongoDB sessionCache | - |
MONGO_DATABASE              | The database where sessions are cached| - |
SAML_SESSION_HEADER | The name of the Cookie and HTTP header which stores the sessionID | - |
SAML_SESSION_EXPIRY_HOURS | The number of hours that the Session is valid. This is only used when the IDP does not provide expiry on the Saml assertion| - |
SAML_AUDIENCE_RESTRICTION | The audience for the SAML protocol | - | 
SAML_IDP_METADATAURL | The URL where SAML metadata can be downloaded from the IDP | - |
SAML_ENTITY_ID | The SAML entityID | - |
SAML_SIGN_AUTH_REQUEST | Controls whether SAML requests are signed or not |-|
SAML_SIGN_CERT_FILE | Certificate file for signing SAML requests | - |
SAML_SIGN_KEY_FILE | Private key file for signing SAML requests | - | 
SAML_ASSERTION_CONSUMER_URL |  The callback URL to use IDP login callbacks, must be a fully qualified URL | - |
SAML_SLO_CONSUMER_URL | The callback URL to use for IDP Logout callbacks, must be a fully qualified URL | - |
SAML_COOKIE_PATH | The path where the session cookie will be valid | - |
SAML_COOKIE_DOMAIN | The domain where the session will be valid | - |
SAML_EXTERNAL_URL | The external URL where the IDP will do callbacks to the service | - | 
SAML_SSO_PATH | The SAML URL to use for login callbacks | /saml/SSO |
SAML_METADATA_PATH | The path where SAML metadata are provided | /saml/metadata |
SAML_LOGOUT_PATH | The path where SAML logout is initiated | /saml/logout | 
SAML_SLO_PATH | The path where the IDP should sent LogoutResponse | /saml/SLO | 
SAML_BACKEND_HOST | The hostname for the backend service| - |
SAML_BACKEND_PORT | The portname for the backend service | - | 