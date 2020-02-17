* Start testing environment

```docker-compose -f testgosamlserviceprovider/docker-compose.yml up -d```

* Build the SamlProvider, this will also run the tests

```docker build  -t kvalitetsit/gosamlserviceprovider --network testgosamlserviceprovider_gosamlserviceprovider .```

* Build the Caddy module
```docker build  -t kvalitetsit/caddysamlprovider  -f Dockerfile-caddy .```

* Build the Caddy templates
```docker build  -t kvalitetsit/caddysamltemplates  -f Dockerfile-caddytemplates .```
