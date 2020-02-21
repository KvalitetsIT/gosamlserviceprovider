#!/bin/bash
`docker run --network testgosamlserviceprovider_gosamlserviceprovider busybox /bin/wget -S http://keycloak:8080/auth/realms/test/protocol/saml/descriptor`
status=$?
max_iterations=50
n=1
until [ $status -eq 0 ];
do
  n=$(expr $n + 1)
  echo "Waiting for keycloak to start. Iteration $n"
  sleep 5s
  `docker run --network testgosamlserviceprovider_gosamlserviceprovider busybox /bin/wget -S http://keycloak:8080/auth/realms/test/protocol/saml/descriptor`
  status=$?
  if [ $n -gt $max_iterations ]; then
     echo "Keycloak didn't come up"
     exit 1
  fi
done
