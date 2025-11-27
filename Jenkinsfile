pipeline {
    agent any

    tools {
        maven 'MAVEN3'
        jdk 'JDK17'
    }

    environment {
        SONAR_TOKEN = credentials('sonar-token')
    }

    stages {
        stage('Checkout') {
            steps {
                deleteDir()
                checkout([$class: 'GitSCM',
                          branches: [[name: 'main']],
                          userRemoteConfigs: [[url: 'https://github.com/4tnx/devsecops']]
                ])
            }
        }

        stage('Semgrep SAST') {
            steps {
                sh '''
                echo "Running Semgrep…"
                docker run --rm -v $PWD:/src returntocorp/semgrep \
                    semgrep --config=p/owasp-top-ten /src > semgrep-report.json
                '''
                archiveArtifacts artifacts: 'semgrep-report.json', allowEmptyArchive: true
            }
        }

        stage('SpotBugs Analysis') {
            steps {
                sh 'mvn clean compile spotbugs:spotbugs || true'
                sh 'mvn spotbugs:spotbugs || true'
                archiveArtifacts artifacts: 'target/spotbugsXml.xml', allowEmptyArchive: true
                archiveArtifacts artifacts: 'target/site/spotbugs.html', allowEmptyArchive: true
            }
        }

        stage('Build + Test') {
            steps {
                sh 'mvn clean verify -DskipTests=false'
            }
        }

        stage('Verify Workspace') {
            steps {
                sh '''
                    echo "Current directory: $(pwd)"
                    echo "Files in workspace:"
                    ls -la
                '''
            }
        }

        stage('Build Docker Image') {
            steps {
                sh 'docker build -f $WORKSPACE/Dockerfile -t testfoodfreezy $WORKSPACE'
            }
        }

        stage('Trivy Scan') {
            steps {
                sh '''
                echo "Running Trivy vulnerability scan..."
                mkdir -p trivy_reports
                
                # Update database and run scan
                trivy image --download-db-only
                trivy image \
                    --format template \
                    --template "@/usr/local/share/trivy/templates/html.tpl" \
                    -o trivy_reports/trivy-report.html \
                    testfoodfreezy || true
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'trivy_reports/*.html', allowEmptyArchive: true
                }
            }
        }

        stage('OWASP Dependency-Check') {
            steps {
                dependencyCheck additionalArguments: '''
                    --scan "./target"
                    --enableExperimental
                    -f "HTML"
                    --prettyPrint
                ''', odcInstallation: 'DP-Check'
                dependencyCheckPublisher pattern: 'dependency-check-report.xml'
                archiveArtifacts artifacts: 'dependency-check-report.html', allowEmptyArchive: true
            }
        }

        stage('Secrets Scan - Gitleaks') {
            steps {
                script {
                    sh "mkdir -p ${WORKSPACE}/secrets_reports"
                    sh """
                    docker run --rm -v ${WORKSPACE}:/code zricethezav/gitleaks:latest detect \
                        --source=/code \
                        --report-format=json \
                        --report-path=/code/secrets_reports/gitleaks-report.json || true
                    """
                }
                archiveArtifacts artifacts: 'secrets_reports/*.json', allowEmptyArchive: true
            }
        }

        stage('Run WebApp') {
            steps {
                sh '''
                # Kill any existing process on port 8080
                pkill -f "java -jar target/*.jar" || true
                sleep 2
                
                # Start application
                nohup java -jar target/*.jar > app.log 2>&1 &
                
                # Wait for application to start
                for i in {1..30}; do
                    if curl -s http://localhost:8080/ > /dev/null; then
                        echo "Application is up!"
                        break
                    fi
                    echo "Waiting for app to be ready... ($i/30)"
                    sleep 2
                done
                '''
            }
        }

        stage("ZAP Scan") {
            steps {
                script {
                    sh "docker rm -f zap 2>/dev/null || true"
                    sh """
                        docker run -d --network host --name zap ghcr.io/zaproxy/zaproxy:stable sleep infinity
                    """
                    sh "docker exec zap mkdir -p /zap/wrk"

                    // Wait for app to be fully ready
                    sleep 30

                    def zapExit = sh(
                        script: "docker exec zap zap-full-scan.py -t http://localhost:8080 -r /zap/report.html -I",
                        returnStatus: true
                    )

                    sh "mkdir -p ${WORKSPACE}/zap_reports"
                    sh "docker cp zap:/zap/report.html ${WORKSPACE}/zap_reports/report.html"

                    echo "ZAP scan finished with exit code: ${zapExit}"
                }
            }
            post {
                always {
                    archiveArtifacts artifacts: 'zap_reports/*.html', allowEmptyArchive: true
                    sh "docker rm -f zap || true"
                    // Stop the application after ZAP scan
                    sh 'pkill -f "java -jar target/*.jar" || true'
                }
            }
        }

        stage('Sonar Analysis') {
            steps {
                withSonarQubeEnv('SonarQubeServer') {
                    sh "mvn sonar:sonar -Dsonar.projectKey=devops_java -Dsonar.host.url=http://192.168.50.4:9000 -Dsonar.login=${SONAR_TOKEN}"
                }
            }
        }

        stage('Quality Gate') {
            steps {
                timeout(time: 1, unit: 'MINUTES') {
                    waitForQualityGate abortPipeline: false
                }
            }
        }
    }

    post {
        always {
            script {
                def buildStatus = currentBuild.currentResult
                def buildUser = currentBuild.getBuildCauses('hudson.model.Cause$UserIdCause')[0]?.userId ?: 'GitHub User'
                def buildUrl = "${env.BUILD_URL}"

                sh '''
                    mkdir -p reports
                    cp semgrep-report.json reports/ 2>/dev/null || true
                    cp target/spotbugsXml.xml reports/ 2>/dev/null || true
                    cp target/site/spotbugs.html reports/ 2>/dev/null || true
                    cp dependency-check-report.html reports/ 2>/dev/null || true
                    cp secrets_reports/*.json reports/ 2>/dev/null || true
                    cp zap_reports/*.html reports/ 2>/dev/null || true
                    cp trivy_reports/*.html reports/ 2>/dev/null || true
                '''

                sh 'echo "--- Reports Collected ---" && ls -la reports || true'

                sh '''
                    if command -v zip >/dev/null 2>&1; then
                        zip -r reports.zip reports/
                    else
                        tar -czf reports.tar.gz reports/
                    fi
                '''

                emailext(
                    to: 'mekni.amin75@gmail.com',
                    subject: "📊 Security Pipeline ${buildStatus} - ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                    body: """
                        <p>Hello,</p>
                        <p>The security pipeline has completed with status: <b>${buildStatus}</b>.</p>
                        <ul>
                            <li><b>Project:</b> ${env.JOB_NAME}</li>
                            <li><b>Build Number:</b> ${env.BUILD_NUMBER}</li>
                            <li><b>Triggered by:</b> ${buildUser}</li>
                            <li><b>Jenkins Build URL:</b> <a href="${buildUrl}">${buildUrl}</a></li>
                        </ul>
                        <p>All generated reports (Semgrep, SpotBugs, Dependency-Check, Secrets, Trivy, and ZAP) are attached.</p>
                        <hr>
                        <p>— Jenkins CI/CD Security Pipeline</p>
                    """,
                    mimeType: 'text/html',
                    attachmentsPattern: 'reports/**',
                    attachLog: true
                )
            }
        }
    }
}