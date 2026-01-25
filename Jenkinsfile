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
                        dotnet ${scannerHome}/SonarScanner.MSBuild.dll begin /k:"SecureApp"
                        dotnet restore IntelligentDevSecOpsPipeline.sln
                        dotnet build IntelligentDevSecOpsPipeline.sln
                        dotnet ${scannerHome}/SonarScanner.MSBuild.dll end
                        """
                    }
                }
            }
        }
    }
}

