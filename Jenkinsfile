pipeline {
    agent any

    environment {
        CLIENT_ID = '123e4567-e89b-12d3-a456-426614174001'
        CLIENT_SECRET = '7a91d1c9-2583-4ef6-8907-7c974f1d6a0e'
        APPLICATION_ID = '65e07ecef30e83d820b00d55'
        SCA_API_URL = 'https://appsecops-api.intruceptlabs.com/api/v1/integrations/performSCAScan'
    }

    stages {
        stage('Checkout Code') {
            steps {
                // Checkout the code from the repository
                checkout scm
            }
        }

        stage('Set Up Python') {
            steps {
                // Set up Python environment
                sh 'python3 -m venv venv'
                sh '. venv/bin/activate && pip install --upgrade pip'
            }
        }

        stage('Install Dependencies') {
            steps {
                // Install project dependencies
                sh '. venv/bin/activate && pip install -r requirements.txt'
            }
        }

        stage('Create ZIP File') {
            steps {
                // Create a ZIP file of the project for SCA scan
                sh 'zip -r project.zip . -x "*.git*"'
            }
        }

        stage('Perform SCA Scan') {
            steps {
                script {
                    // Perform SCA scan using the API
                    def response = sh(script: '''
                        curl -X POST \\
                        -H "Client-ID: $CLIENT_ID" \\
                        -H "Client-Secret: $CLIENT_SECRET" \\
                        -F "projectZipFile=@project.zip" \\
                        -F "applicationId=$APPLICATION_ID" \\
                        -F "scanName=New SCA Scan from Jenkins Pipeline" \\
                        -F "language=python" \\
                        $SCA_API_URL
                    ''', returnStdout: true).trim()

                    def jsonResponse = readJSON(text: response)
                    def canProceed = jsonResponse.canProceed
                    def vulnsTable = jsonResponse.vulnsTable

                    // Output vulnerabilities and scan result
                    echo "Vulnerabilities found during SCA:"
                    echo vulnsTable
                    env.CAN_PROCEED = canProceed
                }
            }
        }

        stage('Check SCA Result') {
            when {
                expression { return env.CAN_PROCEED != 'true' }
            }
            steps {
                // Fail the build if SCA scan did not pass
                error "SCA scan failed. Deployment cancelled."
            }
        }
    }
}

