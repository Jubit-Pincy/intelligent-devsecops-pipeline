parameters {
    string(name: 'PROJECT_KEY', defaultValue: 'SecureApp', description: 'SonarQube Project Key')
    string(name: 'SONAR_URL', defaultValue: 'http://localhost:9000', description: 'SonarQube URL')
}
pipeline {
    environment {
    PROJECT_KEY = "${params.PROJECT_KEY}"
    SONAR_URL = "${params.SONAR_URL}"
    }
    agent any
    
    stages {
        stage('Checkout') {
            steps {
                git branch: 'main',
                    credentialsId: 'github-jenkins',
                    url: 'https://github.com/Jubit-Pincy/intelligent-devsecops-pipeline.git'
            }
        }

        stage('SonarQube Analysis') {
            steps {
                script {
                    def scannerHome = tool 'SonarScanner for MSBuild'

                    withSonarQubeEnv('SonarQube') {
                        sh """
                        dotnet ${scannerHome}/SonarScanner.MSBuild.dll begin \
                            /k:"${PROJECT_KEY}" \
                            /d:sonar.exclusions=reports/**,**/bin/**,**/obj/**
                        dotnet restore IntelligentDevSecOpsPipeline.sln
                        dotnet test IntelligentDevSecOpsPipeline.sln --collect:"XPlat Code Coverage"
                        dotnet ${scannerHome}/SonarScanner.MSBuild.dll end
                        """
                    }
                }
            }
        }

        stage('Wait for Sonar Processing') {
            steps {
                withCredentials([string(credentialsId: 'sonar-token', variable: 'SONAR_TOKEN')]) {
                    script {
                        sh '''
                        echo "TASK_ID: $TASK_ID"
                        echo "SONAR_HOST_URL: $SONAR_HOST_URL"
                        echo "Waiting for Sonar analysis to finish..."

                        TASK_ID=$(grep -oP 'ce/task\\?id=\\K.*' .sonarqube/out/.sonar/report-task.txt)

                        STATUS="PENDING"
                        COUNT=0
                        MAX_ATTEMPTS=20

                        while [ "$STATUS" != "SUCCESS" ] && [ $COUNT -lt $MAX_ATTEMPTS ]; do

                            STATUS=$(curl -s -u $SONAR_TOKEN: \
                            "$SONAR_HOST_URL/api/ce/task?id=$TASK_ID" \
                            | jq -r '.task.status')

                            echo "Sonar status: $STATUS"

                            if [ "$STATUS" = "FAILED" ]; then
                                echo "Sonar analysis failed"
                                exit 1
                            fi

                            COUNT=$((COUNT+1))
                            sleep 3
                        done

                        if [ "$STATUS" != "SUCCESS" ]; then
                            echo "Sonar analysis timeout"
                            exit 1
                        fi

                        echo "Sonar analysis completed."
                        '''
                    }
                }
            }
        }

        stage('Risk Evaluation') {
            steps {
                withCredentials([string(credentialsId: 'sonar-token', variable: 'SONAR_TOKEN')]) {
                    script {
                        def output = sh(
                            script: '''
                            export SONAR_TOKEN=$SONAR_TOKEN
                            export PROJECT_KEY=$PROJECT_KEY
                            export SONAR_URL=$SONAR_URL

                            python3 risk-engine/risk-analyzer.py
                            ''',
                            returnStdout: true
                        ).trim()

                        echo output

                        if (output.contains("BUILD BLOCKED")) {
                            error("Pipeline stopped due to HIGH risk")
                        }

                        if (output.contains("MANUAL SECURITY REVIEW REQUIRED")) {
                            currentBuild.result = 'UNSTABLE'
                        }
                    }
                }
            }
        }
        stage('Deploy Application') {
        steps {
            // 1. Build locally with a memory limit if needed
            sh 'docker build --no-cache -t secureapp .'

            // 2. Atomic Swap (Stop and Start)
            sh '''
            docker stop secureapp-container || true
            docker rm secureapp-container || true
            docker run -d -p 8081:5000 --memory="512m" --name secureapp-container secureapp
            '''

            // 3. THE CLEANER: This is vital for 128GB storage
            // This removes unused images and build cache immediately
            sh 'docker image prune -f'
        }
    }   
}
post {
    always {
        archiveArtifacts artifacts: 'reports/*.html'
    }
}
}
