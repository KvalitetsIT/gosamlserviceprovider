Start testing environment
docker-compose -f testgosamlserviceprovider/docker-compose.yml up -d
Build the docker image, this will also run the tests
docker build  -t kvalitetsit/gosamlserviceprovider --network testgosamlserviceprovider_gosamlserviceprovider .
