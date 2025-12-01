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

        stage('Collect Reports & Notify') {
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

                    // Archive all reports
                    archiveArtifacts artifacts: 'all_reports/**', allowEmptyArchive: true
                    
                    // Store build status for email
                    sh 'echo "BUILD_STATUS=${currentBuild.currentResult}" > build_status.env'
                    sh 'echo "BUILD_NUMBER=${env.BUILD_NUMBER}" >> build_status.env'
                    sh 'echo "JOB_NAME=${env.JOB_NAME}" >> build_status.env'
                    
                    // Slack notification
                    sh """
                    curl -X POST -H 'Content-type: application/json' \
                    --data '{"text": "🔔 Jenkins Build ${currentBuild.currentResult}: ${env.JOB_NAME} #${env.BUILD_NUMBER}"}' \
                    $SLACK_WEBHOOK
                    """
                }
            }
            post {
                always {
                    // Send email without workspace dependencies
                    script {
                        def buildStatus = sh(script: 'cat build_status.env | grep BUILD_STATUS | cut -d= -f2', returnStdout: true).trim()
                        def buildNumber = sh(script: 'cat build_status.env | grep BUILD_NUMBER | cut -d= -f2', returnStdout: true).trim()
                        def jobName = sh(script: 'cat build_status.env | grep JOB_NAME | cut -d= -f2', returnStdout: true).trim()
                        
                        emailext(
                            to: 'mekni.amin75@gmail.com',
                            subject: "📌 Jenkins Security Pipeline - ${buildStatus} | ${jobName} #${buildNumber}",
                            body: """
                                <html>
                                <body>
                                    <h2>🔐 DevSecOps Pipeline Report</h2>
                                    <p>Hello,</p>
                                    
                                    <p>The pipeline has completed with the following details:</p>
                                    
                                    <ul>
                                        <li><b>Status:</b> ${buildStatus}</li>
                                        <li><b>Project:</b> ${jobName}</li>
                                        <li><b>Build Number:</b> ${buildNumber}</li>
                                        <li><b>Build URL:</b> <a href="${env.BUILD_URL}">${env.BUILD_URL}</a></li>
                                    </ul>
                                    
                                    <hr>
                                    <h3>📄 Security Scans Performed</h3>
                                    <ul>
                                        <li>Semgrep SAST</li>
                                        <li>SpotBugs</li>
                                        <li>OWASP Dependency Check</li>
                                        <li>Gitleaks Secrets Scan</li>
                                        <li>Trivy Container Scan</li>
                                        <li>ZAP DAST Scan</li>
                                        <li>SonarQube Analysis</li>
                                    </ul>
                                    
                                    <p>All reports are archived in Jenkins and can be downloaded from the build page.</p>
                                    <hr>
                                    
                                    <p style="font-size:12px;color:#777;">✔ Automated by Jenkins DevSecOps Pipeline</p>
                                </body>
                                </html>
                            """,
                            mimeType: 'text/html',
                            attachLog: true
                        )
                    }
                }
            }
        }
    }
}