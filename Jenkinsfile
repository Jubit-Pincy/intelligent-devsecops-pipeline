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
        stage('Quality Gate Check') {
            steps {
                timeout(time: 2, unit: 'MINUTES') {
                    waitForQualityGate abortPipeline: false
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
stage('Deployment Simulation') {
    when {
        expression { currentBuild.result == null || currentBuild.result == 'SUCCESS' }
    }
    steps {
        echo "Deploying application to STAGING environment..."
        sh 'echo Deployment successful!'
    }
}
}
post {
    always {
        archiveArtifacts artifacts: 'reports/*.html'
    }
}
}
