# Developer guide

## Using Go private modules
This repository uses a private GO module, to download this set the following Env:
```
export GOPRIVATE="github.com/KvalitetsIT/gosecurityprotocol"
```
and add this in your git config
```
[url "ssh://git@github.com/"]
	insteadOf = https://github.com/
```
Now you should be able to go mod download





## Start testing environment
There is a docker-compose setup, that contains a IDP (keycloak) a backend service and a mongo for session caching.
```docker-compose -f testgosamlserviceprovider/docker-compose-dev.yml up -d```

After this has been setup the module can be build using:
```
docker build  -t kvalitetsit/gosamlserviceprovider --network testgosamlserviceprovider_gosamlserviceprovider .
docker build  -t kvalitetsit/caddysamlprovider  -f Dockerfile-caddy .
docker build  -t kvalitetsit/caddysamltemplates  -f Dockerfile-caddytemplates .
```
Finally the caddy server with the SAML module can be started using:
```
docker-compose -f testgosamlserviceprovider/docker-compose-caddy-dev.yml build
docker-compose -f testgosamlserviceprovider/docker-compose-caddy-dev.yml up
```

If you want to run the test from your IDE are command prompt, you to add the following to your hosts file: 
```
127.0.0.1 keycloak
127.0.0.1 mongo
```

