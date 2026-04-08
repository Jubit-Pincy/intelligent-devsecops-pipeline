parameters {
    string(name: 'PROJECT_KEY', defaultValue: 'SecureApp', description: 'SonarQube Project Key')
    string(name: 'SONAR_URL', defaultValue: 'http://localhost:9000', description: 'SonarQube URL')
    string(name: 'WEIGHT_BUGS', defaultValue: '3', description: 'Weight for bugs')
    string(name: 'WEIGHT_VULNS', defaultValue: '5', description: 'Weight for vulnerabilities')
    string(name: 'WEIGHT_HOTSPOTS', defaultValue: '2', description: 'Weight for security hotspots')
}
pipeline {
    environment {
    PROJECT_KEY = "${env.GIT_URL.replaceFirst(/^.*\/([^\/]+)\.git$/, '$1')}"
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
                script {
                    // 1. .NET Strategy (Requires MSBuild Scanner)
                    if (env.PROJECT_TYPE == 'dotnet') {
                    def scannerHome = tool 'SonarScanner for MSBuild'
                        withSonarQubeEnv('SonarQube') {
                        sh """
                            # 1. Start Sonar
                            dotnet ${scannerHome}/SonarScanner.MSBuild.dll begin /k:${PROJECT_KEY} \
                                /d:sonar.cs.opencover.reportsPaths="**/coverage.opencover.xml"
                        
                            # 2. Build
                            dotnet build SolutionFile.sln -c Release
                        
                            # 3. Run Tests and Force the Output to the Root
                            # We use -p:CoverletOutput=../ to move it from the test folder to the workspace root
                            dotnet test SolutionFile.sln --no-build -c Release \
                                /p:CollectCoverage=true \
                                /p:CoverletOutputFormat=opencover \
                                /p:CoverletOutput="../coverage.opencover.xml"
                        
                            # 4. End Sonar
                            dotnet ${scannerHome}/SonarScanner.MSBuild.dll end
                        """
                        }
                    }
                    // 2. Java Strategy (Requires Maven/Gradle Scanner)
                    else if (env.PROJECT_TYPE == 'java') {
                        withSonarQubeEnv('SonarQube') {
                            if (fileExists('pom.xml')) {
                                sh "mvn clean verify sonar:sonar -Dsonar.projectKey=${PROJECT_KEY}"
                            } else if (fileExists('build.gradle')) {
                                sh "./gradlew sonar -Dsonar.projectKey=${PROJECT_KEY}"
                            }
                        }
                    }
                    // 3. Universal Strategy (TS, JS, Python, C++, Go, PHP, etc.)
                    else {
                        withSonarQubeEnv('SonarQube') {
                            // C++ special provision: check for build-wrapper
                            if (fileExists('CMakeLists.txt') || fileExists('Makefile')) {
                                echo "C/C++ Detected: Use build-wrapper if available"
                            }
                            sh "sonar-scanner -Dsonar.projectKey=${PROJECT_KEY} -Dsonar.sources=."
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

                            export SONAR_TOKEN=\$SONAR_TOKEN
                            export PROJECT_KEY=\$PROJECT_KEY
                            export SONAR_URL=\$SONAR_URL
                            
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
                    // 1. Generate dynamic names based on the PROJECT_KEY
                    // We use toLowerCase() because Docker image names cannot have capitals
                    def imageName = "${env.PROJECT_KEY.toLowerCase()}"
                    def containerName = "${imageName}-container"
                    
                    // 2. Map ports based on project type (to keep your existing structure)
                    def portMap = [
                        'dotnet': '8081:5000',
                        'node'  : '8082:3000',
                        'python': '8083:5000',
                        'java'  : '8084:8080'
                    ]
                    def ports = portMap[env.PROJECT_TYPE] ?: '8080:8080'
        
                    echo "Deployment Strategy → Project: ${imageName}, Type: ${env.PROJECT_TYPE}, Port: ${ports}"
        
                    // 3. Single dynamic shell block for all project types
                    sh """
                        docker build -t ${imageName} .
                        docker stop ${containerName} || true
                        docker rm ${containerName} || true
                        docker run -d -p ${ports} --name ${containerName} ${imageName}
                    """
        
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
