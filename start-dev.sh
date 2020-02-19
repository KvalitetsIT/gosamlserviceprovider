#!/bin/bash
echo Starting Keycloak and MongoDB
docker-compose -f testgosamlserviceprovider/docker-compose.yml up -d
echo Starting echo service
docker-compose -f testgosamlserviceprovider/docker-compose-echo.yml up -d
echo Building gosamlserviceprovider
docker build  -t kvalitetsit/gosamlserviceprovider --network testgosamlserviceprovider_gosamlserviceprovider .
echo Building caddy module
docker build  -t kvalitetsit/caddysamlprovider --no-cache  -f Dockerfile-caddy .
echo Building caddy templates
docker build  -t kvalitetsit/caddysamltemplates --no-cache  -f Dockerfile-caddytemplates .
echo Starting Caddy with SAML module
docker-compose -f testgosamlserviceprovider/docker-compose-caddy.yml down
docker-compose -f testgosamlserviceprovider/docker-compose-caddy.yml build
docker-compose -f testgosamlserviceprovider/docker-compose-caddy.yml up
