podTemplate(
        containers: [containerTemplate(image: 'kvalitetsit/docker-compose:dev', name: 'docker', command: 'cat', ttyEnabled: true)],
        volumes: [hostPathVolume(hostPath: '/var/run/docker.sock', mountPath: '/var/run/docker.sock')],
) {
    node(POD_LABEL) {
        properties([disableConcurrentBuilds()])
        try {
            stage('Clone repository') {
                checkout scm
            }

            stage('Make sure that the testenvironments starts from clean') {
                container('docker') {
                    dir('testgosamlserviceprovider') {
                        sh 'docker-compose rm -f'
                        sh 'docker-compose -f docker-compose-caddy.yml rm -f'
                    }
                }
            }

            stage('Startup the testenvironment used by the integration tests') {
                container('docker') {
                    dir('testgosamlserviceprovider') {
                        sh 'docker-compose up -d'
                        sh 'ls -l'
                        sh 'waitforkeycloak.sh'
                    }
                }
            }

            stage('Build Docker image (oioidwsrest module)') {
                container('docker') {
                    docker.build("kvalitetsit/caddysamlprovider", "--network testgosamlserviceprovider_gosamlserviceprovider .")
                }
            }
        } finally {
            container('docker') {
                stage('Clean up') {
                    dir('testgosamlserviceprovider') {
                        sh 'docker-compose -f docker-compose-caddy.yml stop'
                        sh 'docker-compose stop'
                    }
                }
            }
        }
    }
}

