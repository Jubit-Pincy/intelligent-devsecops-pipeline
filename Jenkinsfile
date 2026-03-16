pipeline {
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
                        dotnet ${scannerHome}/SonarScanner.MSBuild.dll begin /k:\"SecureApp\" /d:sonar.exclusions=reports/**
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
                script {
                    sh '''
                    echo "Waiting for Sonar analysis to finish..."
        
                    TASK_ID=$(grep -oP 'ce/task\\?id=\\K.*' .sonarqube/out/.sonar/report-task.txt)
        
                    STATUS="PENDING"
        
                    while [ "$STATUS" != "SUCCESS" ]; do
                        STATUS=$(curl -s -u $SONAR_TOKEN: \
                        "http://localhost:9000/api/ce/task?id=$TASK_ID" \
                        | jq -r '.task.status')
        
                        echo "Sonar status: $STATUS"
        
                        if [ "$STATUS" = "FAILED" ]; then
                            echo "Sonar analysis failed"
                            exit 1
                        fi
        
                        sleep 3
                    done
        
                    echo "Sonar analysis completed."
                    '''
                }
            }
        }

	    stage('Risk Evaluation') {
            steps {
                withCredentials([string(credentialsId: 'sonar-token', variable: 'SONAR_TOKEN')]) {
                    script {
                        def output = sh(
                            script: 'python3 risk-engine/risk-analyzer.py',
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
