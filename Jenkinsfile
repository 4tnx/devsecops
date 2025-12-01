pipeline {

    agent {
        docker {
            image 'maven:3.9.9-eclipse-temurin-17'
            args '-v /var/run/docker.sock:/var/run/docker.sock'
        }
    }

    tools {
        maven 'MAVEN3'
        jdk 'JDK17'
    }

    environment {
        SONAR_TOKEN = credentials('sonar-token')
        NVD_API_KEY = credentials('8ee6ac6e-8bc-4163-889a-1245e99546c5')
        SLACK_WEBHOOK = credentials('slackcred')
    }

    stages {

        stage('Checkout') {
            steps {
                deleteDir()
                checkout scm
            }
        }

        stage('Parallel SAST Scanning') {
            parallel {

                stage('Semgrep') {
                    steps {
                        sh '''
                        echo "Running Semgrep..."
                        docker run --rm \
                          -v $PWD:/src returntocorp/semgrep semgrep \
                          --config=p/owasp-top-ten /src \
                          > semgrep-report.json
                        '''
                        archiveArtifacts 'semgrep-report.json'
                    }
                }

                stage('SpotBugs') {
                    steps {
                        sh 'mvn clean compile spotbugs:spotbugs || true'
                        archiveArtifacts 'target/spotbugsXml.xml'
                        archiveArtifacts 'target/site/spotbugs.html'
                    }
                }

                stage('Gitleaks') {
                    steps {
                        sh "mkdir -p secrets_reports"
                        sh '''
                        docker run --rm -v $PWD:/code \
                          zricethezav/gitleaks:latest detect \
                          --source=/code \
                          --report-format=json \
                          --report-path=/code/secrets_reports/gitleaks.json
                        '''
                        archiveArtifacts 'secrets_reports/*.json'
                    }
                }
            }
        }

        stage('Build & Test') {
            steps {
                sh 'mvn clean verify -DskipTests=false'
            }
        }

        stage('Build Docker Image') {
            steps {
                sh 'docker build -t testfoodfreezy .'
            }
        }

        stage('Trivy Image Scan (HOST INSTALL)') {
            steps {
                sh '''
                mkdir -p trivy_reports
                trivy image \
                  --format template \
                  --template "$(trivy -h | grep -oP '/.*html.tpl')" \
                  -o trivy_reports/trivy-report.html \
                  testfoodfreezy \
                  || true
                '''
            }
            post {
                always {
                    archiveArtifacts 'trivy_reports/*.html'
                }
            }
        }

        stage('OWASP Dependency-Check') {
            steps {
                dependencyCheck additionalArguments: '''
                    --enableExperimental
                    --scan ./target
                    --format ALL
                ''', odcInstallation: 'DP-Check'

                dependencyCheckPublisher pattern: 'dependency-check-report.xml'
                archiveArtifacts 'dependency-check-report.*'
            }
        }

        stage('Run WebApp') {
            steps {
                sh '''
                nohup java -jar target/*.jar > app.log 2>&1 &
                for i in {1..25}; do
                    if curl -s http://localhost:8080 > /dev/null; then
                        echo "App ready!"
                        exit 0
                    fi
                    echo "Waiting for app..."
                    sleep 2
                done
                exit 1
                '''
            }
        }

        stage('ZAP Full Scan') {
            steps {
                script {
                    sh "docker rm -f zap || true"

                    sh "docker run -d --network host --name zap ghcr.io/zaproxy/zaproxy:stable sleep infinity"

                    sh "docker exec zap mkdir -p /zap/wrk"

                    def exitCode = sh(
                        script: "docker exec zap zap-full-scan.py -t http://localhost:8080 -r /zap/report.html",
                        returnStatus: true
                    )

                    sh "mkdir -p zap_reports"
                    sh "docker cp zap:/zap/report.html zap_reports/report.html"

                    if (exitCode == 1 || exitCode == 3) {
                        error "ZAP scan failed"
                    }
                }
            }
            post {
                always {
                    archiveArtifacts 'zap_reports/*.html'
                    sh "docker rm -f zap || true"
                }
            }
        }

        stage('SonarQube Analysis') {
            steps {
                withSonarQubeEnv('SonarQubeServer') {
                    sh """
                        mvn sonar:sonar \
                        -Dsonar.projectKey=devops_java \
                        -Dsonar.host.url=http://192.168.50.4:9000 \
                        -Dsonar.login=$SONAR_TOKEN
                    """
                }
            }
        }

        stage('Sonar Quality Gate') {
            steps {
                timeout(time: 2, unit: 'MINUTES') {
                    waitForQualityGate abortPipeline: true
                }
            }
        }

        stage('Post Build Actions') {
            steps {
                script {
                    // --- Collect all reports ---
                    sh '''
                        mkdir -p all_reports
                        cp semgrep-report.json all_reports/ 2>/dev/null || true
                        cp target/spotbugsXml.xml all_reports/ 2>/dev/null || true
                        cp target/site/spotbugs.html all_reports/ 2>/dev/null || true
                        cp dependency-check-report.* all_reports/ 2>/dev/null || true
                        cp secrets_reports/* all_reports/ 2>/dev/null || true
                        cp trivy_reports/* all_reports/ 2>/dev/null || true
                        cp zap_reports/* all_reports/ 2>/dev/null || true
                        cp app.log all_reports/ 2>/dev/null || true
                    '''

                    archiveArtifacts artifacts: 'all_reports/**', allowEmptyArchive: true

                    // Slack notification
                    sh """
                    curl -X POST -H 'Content-type: application/json' \
                    --data '{"text": "🔔 Jenkins Build ${currentBuild.currentResult}: ${env.JOB_NAME} #${env.BUILD_NUMBER}"}' \
                    $SLACK_WEBHOOK
                    """
                }
            }
        }
    }

    post {
        always {
            emailext(
                to: 'mekni.amin75@gmail.com',
                subject: "📌 Jenkins Security Pipeline - ${currentBuild.currentResult} | ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                body: """
                    <html>
                    <body>
                        <h2>🔐 DevSecOps Pipeline Report</h2>
                        <p>Hello,</p>
                        
                        <p>The pipeline has completed with the following details:</p>
                        
                        <ul>
                            <li><b>Status:</b> ${currentBuild.currentResult}</li>
                            <li><b>Project:</b> ${env.JOB_NAME}</li>
                            <li><b>Build Number:</b> ${env.BUILD_NUMBER}</li>
                            <li><b>Branch:</b> ${env.GIT_BRANCH}</li>
                            <li><b>Triggered By:</b> ${currentBuild.getBuildCauses('hudson.model.Cause$UserIdCause')[0]?.userId ?: 'GitHub Trigger'}</li>
                            <li><b>Build URL:</b> <a href="${env.BUILD_URL}">${env.BUILD_URL}</a></li>
                        </ul>
                        
                        <hr>
                        <h3>📄 Reports Included</h3>
                        <ul>
                            <li>Semgrep SAST</li>
                            <li>SpotBugs</li>
                            <li>OWASP Dependency Check</li>
                            <li>Gitleaks Secrets Scan</li>
                            <li>Trivy Container Scan</li>
                            <li>ZAP DAST Scan</li>
                        </ul>
                        
                        <p>All reports are attached to this email.</p>
                        <hr>
                        
                        <p style="font-size:12px;color:#777;">✔ Automated by Jenkins DevSecOps Pipeline</p>
                    </body>
                    </html>
                """,
                mimeType: 'text/html',
                attachmentsPattern: 'all_reports/**, app.log',
                attachLog: true
            )
        }
    }
}