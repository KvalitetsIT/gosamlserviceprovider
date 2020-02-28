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
        stage('Build Docker image (caddy templates)') {
            steps {
               script {
                 docker.build("kvalitetsit/caddysamltemplates", "-f Dockerfile-caddytemplates .")
               }
            }
        }
        stage('Build Docker resouce images for caddy samlprovider module') {
            steps {
               script {
                 docker.build("build-samlmodule-resources/caddy", "-f ./testgosamlserviceprovider/Dockerfile-resources-caddytest --no-cache ./testgosamlserviceprovider")
               }
            }
        }
        stage('Run integration tests for caddy module') {
           steps {
              dir('testgosamlserviceprovider') {
                sh 'docker-compose -f docker-compose-caddy.yml up -d'
              }
           }
        }
		stage('Tag Docker image and push to registry') {
		  steps {
			script {
              image = docker.image("kvalitetsit/caddysamlprovider")
              image.push("dev")
              if (env.TAG_NAME != null && env.TAG_NAME.startsWith("v")) {
                   echo "Tagging version."
                   image.push(env.TAG_NAME.substring(1))
                   image.push("latest")
              }
      		}
	      }
		}
        stage('Tag Docker image for templates and push to registry') {
           steps {
             script {
               image = docker.image("kvalitetsit/caddysamltemplates")
               image.push("dev")
               if (env.TAG_NAME != null && env.TAG_NAME.startsWith("v")) {
                  echo "Tagging version."
                  image.push(env.TAG_NAME.substring(1))
                  image.push("latest")
               }
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

