pipeline {
    agent any

    tools {
        maven 'MAVEN3'
        jdk 'JDK17'
    }

    environment {
        SONAR_TOKEN = credentials('sonar-token')
        NVD_API_KEY = credentials('8ee6ac6e-8bc0-4163-889a-1245e99546c5')
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
        sh '''
        echo "Looking for SpotBugs reports..."
        find . -name "spotbugsXml.xml" -type f | head -5
        find . -name "spotbugs.html" -type f | head -5
        '''
        // Try multiple possible locations
        archiveArtifacts artifacts: '**/target/spotbugsXml.xml,**/target/spotbugsXml/**/*.xml,target/**/spotbugs*.xml', allowEmptyArchive: true
        archiveArtifacts artifacts: '**/target/site/spotbugs.html,**/spotbugs.html', allowEmptyArchive: true
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
                trivy image --format template --template "@/usr/local/share/trivy/templates/html.tpl" -o trivy_reports/trivy-report.html testfoodfreezy || true
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'trivy_reports/*.html', allowEmptyArchive: true
                }
            }
        }

        stage('OWASP Dependency-Check Vulnerabilities') {
          steps {
            dependencyCheck additionalArguments: '''
                --scan "./target"
                --enableExperimental
                -f "ALL"
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
                        --report-path=/code/secrets_reports/gitleaks-report.json
                    """
                }
                archiveArtifacts artifacts: 'secrets_reports/*.json'
            }
        }

        stage('Run WebApp') {
    steps {
        sh '''
        # Kill any existing process on port 8089
        fuser -k 8089/tcp 2>/dev/null || true
        
        # Start the application
        nohup java -jar target/FoodFrenzy-0.0.1-SNAPSHOT.jar --server.port=8089 > app.log 2>&1 &
        
        # Wait for application to start
        echo "Waiting for application to start..."
        for i in {1..30}; do
            if curl -s http://localhost:8089/actuator/health > /dev/null 2>&1; then
                echo "✓ Application is up and running!"
                curl -s http://localhost:8089/actuator/health | jq . 2>/dev/null || true
                exit 0
            fi
            echo "Attempt $i/30: Waiting for application..."
            sleep 3
        done
        
        echo "✗ Application failed to start within 90 seconds"
        echo "=== Last 50 lines of app.log ==="
        tail -50 app.log
        exit 1
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

                    def zapExit = sh(
                        script: "docker exec zap zap-full-scan.py -t http://localhost:8089 -r /zap/report.html",
                        returnStatus: true
                    )

                    sh "mkdir -p ${WORKSPACE}/zap_reports"
                    sh "docker cp zap:/zap/report.html ${WORKSPACE}/zap_reports/report.html"

                    echo "ZAP scan finished with exit code: ${zapExit}"

                    if (zapExit == 1 || zapExit == 3) {
                        error "ZAP scan failed"
                    }
                }
            }

            post {
                always {
                    archiveArtifacts artifacts: 'zap_reports/*.html', allowEmptyArchive: true
                    sh "docker rm -f zap || true"
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