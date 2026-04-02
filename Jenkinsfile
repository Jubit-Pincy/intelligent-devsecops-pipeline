parameters {
    string(name: 'PROJECT_KEY', defaultValue: 'ProjectKey', description: 'SonarQube Project Key')
    string(name: 'SONAR_URL', defaultValue: 'http://localhost:9000', description: 'SonarQube URL')
    string(name: 'WEIGHT_BUGS', defaultValue: '3', description: 'Weight for bugs')
    string(name: 'WEIGHT_VULNS', defaultValue: '5', description: 'Weight for vulnerabilities')
    string(name: 'WEIGHT_HOTSPOTS', defaultValue: '2', description: 'Weight for security hotspots')
}
pipeline {
    environment {
    PROJECT_KEY = "${env.PROJECT_KEY}"
    DEFAULT_SONAR_URL = 'http://localhost:9000'
    SONAR_URL = "${params.SONAR_URL ?: DEFAULT_SONAR_URL}"
    WEIGHT_BUGS     = "${params.WEIGHT_BUGS ?: '3'}"
    WEIGHT_VULNS    = "${params.WEIGHT_VULNS ?: '5'}"
    WEIGHT_HOTSPOTS = "${params.WEIGHT_HOTSPOTS ?: '2'}"

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

        stage('Detect Project Type') {
            steps {
                script {
                    if (sh(script: "ls *.sln", returnStatus: true) == 0) {
                        env.PROJECT_TYPE = 'dotnet'
                    } else if (fileExists('package.json')) {
                        env.PROJECT_TYPE = 'node'
                    } else if (fileExists('requirements.txt')) {
                        env.PROJECT_TYPE = 'python'
                    } else if (fileExists('pom.xml')) {
                        env.PROJECT_TYPE = 'java'
                    } else {
                        error("Unsupported project type")
                    }

                    echo "Detected project type: ${env.PROJECT_TYPE}"
                }
            }
        }

        stage('Build & Sonar Analysis') {
            steps {
                withSonarQubeEnv('SonarQube') {
                    script {
                    
                        if (env.PROJECT_TYPE == 'dotnet') {
                        
                            def scannerHome = tool 'SonarScanner for MSBuild'

                            sh """
                            dotnet ${scannerHome}/SonarScanner.MSBuild.dll begin \
                                /k:\$PROJECT_KEY

                            dotnet build IntelligentDevSecOpsPipeline.sln

                            dotnet ${scannerHome}/SonarScanner.MSBuild.dll end
                            """
                        }

                        else if (env.PROJECT_TYPE == 'node') {
                            sh '''
                            npm install
                            sonar-scanner \
                              -Dsonar.projectKey=\$PROJECT_KEY \
                              -Dsonar.sources=.
                            '''
                        }

                        else if (env.PROJECT_TYPE == 'python') {
                            sh '''
                            pip install -r requirements.txt
                            sonar-scanner \
                              -Dsonar.projectKey=\$PROJECT_KEY \
                              -Dsonar.sources=.
                            '''
                        }

                        else if (env.PROJECT_TYPE == 'java') {
                            sh '''
                            mvn clean verify sonar:sonar \
                              -Dsonar.projectKey=\$PROJECT_KEY
                            '''
                        }
                    }
                }
            }
        }

        stage('Wait for Sonar Processing') {
            steps {
                withCredentials([string(credentialsId: 'sonar-token', variable: 'SONAR_TOKEN')]) {
                    script {
                        sh '''
                        echo "Waiting for Sonar analysis to finish..."
                        
                        TASK_ID=$(awk -F= '/ceTaskId/ {print $2}' .sonarqube/out/.sonar/report-task.txt)

                        STATUS="PENDING"
                        COUNT=0
                        MAX_ATTEMPTS=20

                        echo "Using SONAR_URL: \$SONAR_URL"

                        while [ "$STATUS" != "SUCCESS" ] && [ $COUNT -lt $MAX_ATTEMPTS ]; do

                            STATUS=\$(curl -s -u \$SONAR_TOKEN: "\$SONAR_URL/api/ce/task?id=\$TASK_ID" | jq -r '.task.status')

                            echo "Sonar status: $STATUS"

                            if [ "$STATUS" = "FAILED" ]; then
                                echo "Sonar analysis failed"
                                exit 1
                            fi

                            COUNT=$((COUNT+1))
                            sleep 3
                        done
                        echo "TASK_ID: $TASK_ID"
                        echo "SONAR_URL: \$SONAR_URL"
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
                            echo "BUGS=$WEIGHT_BUGS, VULNS=$WEIGHT_VULNS, HOTSPOTS=$WEIGHT_HOTSPOTS"

                            export SONAR_TOKEN=$SONAR_TOKEN
                            export PROJECT_KEY=$PROJECT_KEY
                            export SONAR_URL=$SONAR_URL
                            
                            export WEIGHT_BUGS=$WEIGHT_BUGS
                            export WEIGHT_VULNS=$WEIGHT_VULNS
                            export WEIGHT_HOTSPOTS=$WEIGHT_HOTSPOTS

                            python3 risk-engine/risk-analyzer.py
                            ''',
                            returnStdout: true
                        ).trim()

                        echo output

                        if (output.contains("LOW")) {
                            env.RISK_LEVEL = "LOW"
                        } else if (output.contains("MEDIUM")) {
                            env.RISK_LEVEL = "MEDIUM"
                        } else if (output.contains("HIGH")) {
                            env.RISK_LEVEL = "HIGH"
                        }

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
            when {
                expression { env.RISK_LEVEL != 'HIGH' }
            }
            steps {
                script {
                
                    echo "Deployment Strategy → Type: ${env.PROJECT_TYPE}, Risk: ${env.RISK_LEVEL}"

                    if (env.PROJECT_TYPE == 'dotnet') {
                        sh '''
                        docker build -t secureapp .
                        docker stop secureapp-container || true
                        docker rm secureapp-container || true
                        docker run -d -p 8081:5000 --name secureapp-container secureapp
                        '''
                    }

                    else if (env.PROJECT_TYPE == 'node') {
                        sh '''
                        docker build -t nodeapp .
                        docker run -d -p 8082:3000 --name nodeapp-container nodeapp
                        '''
                    }

                    else if (env.PROJECT_TYPE == 'python') {
                        sh '''
                        docker build -t pythonapp .
                        docker run -d -p 8083:5000 --name pythonapp-container pythonapp
                        '''
                    }

                    else if (env.PROJECT_TYPE == 'java') {
                        sh '''
                        docker build -t javaapp .
                        docker run -d -p 8084:8080 --name javaapp-container javaapp
                        '''
                    }

                    // 🔶 MEDIUM RISK → mark unstable
                    if (env.RISK_LEVEL == 'MEDIUM') {
                        currentBuild.result = 'UNSTABLE'
                        echo "⚠️ Deployment allowed with warnings (MEDIUM risk)"
                    }

                    sh 'docker image prune -f'
                }
            }
        }
    }
post {
    always {
        archiveArtifacts artifacts: 'reports/*.html'
    }
}
}
