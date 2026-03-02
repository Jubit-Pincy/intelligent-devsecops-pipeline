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
                        dotnet ${scannerHome}/SonarScanner.MSBuild.dll begin \  
				/k:"SecureApp" \
				/d:sonar.exclusions=reports/** /d:sonar.cs.opencover.reportsPaths=**/coverage.cobertura.xml
                        dotnet restore IntelligentDevSecOpsPipeline.sln
                        dotnet test IntelligentDevSecOpsPipeline.sln --collect:"XPlat Code Coverage"
                        dotnet ${scannerHome}/SonarScanner.MSBuild.dll end
                        """
                    }
                }
            }
        }

	stage('Risk Evaluation') {
	    steps {
		withCredentials([string(credentialsId: 'sonar-token', variable: 'SONAR_TOKEN')]) {
            sh 'python3 risk-engine/risk-analyzer.py'
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
