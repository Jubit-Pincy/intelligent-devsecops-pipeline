pipeline {
    agent any

    tools {
        MsBuildSQRunnerInstallation 'SonarScanner for MSBuild'
    }

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
                withSonarQubeEnv('SonarQube') {
                    sh '''
                    dotnet $MSBUILD_SCANNER_HOME/SonarScanner.MSBuild.dll begin /k:"SecureApp"
                    dotnet restore IntelligentDevSecOpsPipeline.sln
                    dotnet build IntelligentDevSecOpsPipeline.sln
                    dotnet $MSBUILD_SCANNER_HOME/SonarScanner.MSBuild.dll end
                    '''
                }
            }
        }
    }
}
