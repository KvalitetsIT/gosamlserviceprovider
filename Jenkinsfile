pipeline {
	agent any
        options {
                disableConcurrentBuilds()
        }
	stages {

		stage('Clone repository') {
			steps {
				checkout scm
			}
		}

         stage('Make sure that the testenvironments starts from clean') {
            steps {
               dir('testgosamlserviceprovider') {
                 sh 'docker-compose rm -f'
				 sh 'docker-compose -f docker-compose-caddy.yml rm -f'
               }
            }
		}

		stage('Startup the testenvironment used by the integration tests') {
			steps {
				dir('testgosamlserviceprovider') {
					sh 'docker-compose  --verbose up -d'
					sh './waitforkeycloak.sh'
				}
			}
		}
		stage('Build Docker image (gosamlprovider module)') {
			steps {
				script {
					docker.build("kvalitetsit/caddysamlprovider", "--network testgosamlserviceprovider_gosamlserviceprovider .")
				}
			}
		}
	}
	post {
		always {
			dir('testgosamlserviceprovider') {
                sh 'docker-compose -f docker-compose-caddy.yml stop'
                sh 'docker-compose stop'
			}
		}
	}
}

