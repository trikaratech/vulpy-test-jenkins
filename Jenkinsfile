pipeline {
    agent any

    environment {
        CLIENT_ID = '123e4567-e89b-12d3-a456-426614174001'
        CLIENT_SECRET = '7a91d1c9-2583-4ef6-8907-7c974f1d6a0e'
        APPLICATION_ID = '65e07ecef30e83d820b00d55'
        SCA_API_URL = 'https://appsecops-api.intruceptlabs.com/api/v1/integrations/performSCAScan'
        SAST_API_URL = 'https://appsecops-api.intruceptlabs.com/api/v1/integrations/performSASTScan'
    }

    stages {
        stage('Clean Up Old Files') {
            steps {
                script {
                    // Clean up any previous directories or files
                    sh 'rm -rf venv'
                    sh 'rm -rf project.zip'
                    sh 'rm -rf *.json'
                    sh 'rm -rf *.csv'
                    sh 'rm -rf *.sh'
                }
            }
        }

        stage('Checkout Code') {
            steps {
                // Checkout the code from the repository
                checkout scm
            }
        }

        stage('Create ZIP Files') {
            steps {
                script {
                    // Create project.zip (contains the content of the project), excluding unwanted files
                    sh 'zip -r project.zip . -x "*.git*" -x "venv/*"'
                }
            }
        }

        stage('Perform SCA Scan') {
    steps {
        script {
            // Perform SCA scan using the API
            def response = sh(script: """
                #!/bin/bash
                curl -v -X POST \
                -H "Client-ID: ${CLIENT_ID}" \
                -H "Client-Secret: ${CLIENT_SECRET}" \
                -F "projectZipFile=@project.zip" \
                -F "applicationId=${APPLICATION_ID}" \
                -F "scanName=New SCA Scan from Jenkins Pipeline" \
                -F "language=python" \
                "${SCA_API_URL}"
            """, returnStdout: true).trim()

            echo "SCA API Response: ${response}"
            def jsonResponse = readJSON(text: response)
            def canProceedSCA = jsonResponse.canProceed
            def vulnsTable = jsonResponse.vulnsTable

            // Remove ANSI color codes (if any)
            def cleanVulnsTable = vulnsTable.replaceAll(/\x1B\[[;0-9]*m/, '')

            // Output vulnerabilities and scan result
            echo "Vulnerabilities found during SCA:"
            echo "${cleanVulnsTable}"

            env.CAN_PROCEED_SCA = canProceedSCA.toString()
        }
    }
}

        stage('Check SCA Result') {
            when {
                expression { return env.CAN_PROCEED_SCA != 'true' }
            }
            steps {
                // Fail the build if SCA scan did not pass
                error "SCA scan failed. Deployment cancelled."
            }
        }

        stage('Perform SAST Scan') {
    when {
        expression { return env.CAN_PROCEED_SCA == 'true' }
    }
    steps {
        script {
            // Perform SAST scan using the API
            def response = sh(script: """
                #!/bin/bash
                curl -v -X POST \
                -H "Client-ID: ${CLIENT_ID}" \
                -H "Client-Secret: ${CLIENT_SECRET}" \
                -F "projectZipFile=@project.zip" \
                -F "applicationId=${APPLICATION_ID}" \
                -F "scanName=New SAST Scan from Jenkins Pipeline" \
                -F "language=python" \
                "${SAST_API_URL}"
            """, returnStdout: true).trim()

            echo "SAST API Response: ${response}"
            def jsonResponse = readJSON(text: response)
            def canProceedSAST = jsonResponse.canProceed
            def vulnsTable = jsonResponse.vulnsTable

            // Remove ANSI color codes (if any)
            def cleanVulnsTable = vulnsTable.replaceAll(/\x1B\[[;0-9]*m/, '')

            // Output vulnerabilities and scan result
            echo "Vulnerabilities found during SAST:"
            echo "${cleanVulnsTable}"

            env.CAN_PROCEED_SAST = canProceedSAST.toString()
        }
    }
}

        stage('Check SAST Result') {
            when {
                expression { return env.CAN_PROCEED_SAST != 'true' }
            }
            steps {
                // Fail the build if SAST scan did not pass
                error "SAST scan failed. Deployment cancelled."
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

        // Additional stages (e.g., deploy) can be added here
    }
}
