pipeline {
    agent any

    stages {
        stage('Checkout Code') {
            steps {
                git branch: 'main',
                    credentialsId: 'github-jenkins',
                    url: 'https://github.com/Jubit-Pincy/intelligent-devsecops-pipeline.git'
            }
        }

        stage('Build Application') {
            steps {
                sh '''
                cd SecureApp
                dotnet restore
                dotnet build
                '''
            }
        }
    }
}
