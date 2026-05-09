pipeline {
    agent any

    stages {

        stage('Build') {
            steps {
                sh 'make clean'
                sh "make all"
            }
        }

        stage('Deploy') {
            steps {
                sh 'tar -czf build.tar.gz mini-nids obj/'
            }
        }

    }
}
