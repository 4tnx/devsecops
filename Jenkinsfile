pipeline {
    agent any

    tools {
        maven 'MAVEN3'
        jdk 'JDK17'
    }

    environment {
        SONAR_TOKEN = credentials('sonar-token')
        DOCKER_IMAGE_NAME = 'testfoodfreezy'
    }

    stages {
        stage('Checkout') {
            steps {
                deleteDir()
                checkout([
                    $class: 'GitSCM',
                    branches: [[name: 'main']],
                    userRemoteConfigs: [[
                        url: 'https://github.com/4tnx/devsecops',
                        credentialsId: ''  // Add your credentials ID if needed
                    ]]
                ])
            }
        }

        stage('Semgrep SAST') {
            steps {
                script {
                    sh '''
                    echo "Running Semgrep…"
                    mkdir -p ${WORKSPACE}/semgrep_reports
                    docker run --rm -v ${WORKSPACE}:/src returntocorp/semgrep \
                        semgrep --config=p/owasp-top-ten /src --json \
                        > semgrep-report.json 2>/dev/null || echo "Semgrep completed"
                    '''
                }
            }
            post {
                always {
                    archiveArtifacts artifacts: 'semgrep-report.json', allowEmptyArchive: true
                }
            }
        }

        stage('Spotbugs') {
            steps {
                sh "mvn -B spotbugs:spotbugs || true"
            }
            post {
                always {
                    archiveArtifacts artifacts: 'target/site/spotbugs.html', allowEmptyArchive: true
                }
            }
        }

       stage('Build') {
            steps {
                sh "mvn -B -DskipTests clean package"
            }
        }

        stage('Unit Tests') {
            steps {
                sh "mvn -B test || true"
            }
            post {
                always {
                    junit allowEmptyResults: true, testResults: '**/surefire-reports/*.xml'
                }
            }
        }


        stage('Verify Workspace') {
            steps {
                sh '''
                echo "=== Workspace Verification ==="
                echo "Current directory: $(pwd)"
                echo "Workspace: ${WORKSPACE}"
                echo "Files in workspace:"
                ls -la
                echo "Maven target directory:"
                ls -la target/ 2>/dev/null || echo "target/ directory not found"
                echo "=== End Verification ==="
                '''
            }
        }

        stage('Build Docker Image') {
            steps {
                script {
                    // First, find the correct Dockerfile location
                    sh '''
                    echo "Looking for Dockerfile..."
                    find . -name "Dockerfile" -type f | head -5
                    '''
                    
                    // Try to build with explicit path
                    sh '''
                    DOCKERFILE_PATH=$(find . -name "Dockerfile" -type f | head -1)
                    if [ -n "$DOCKERFILE_PATH" ]; then
                        echo "Found Dockerfile at: $DOCKERFILE_PATH"
                        docker build -f "$DOCKERFILE_PATH" -t ${DOCKER_IMAGE_NAME} .
                    else
                        echo "ERROR: Dockerfile not found!"
                        echo "Creating a basic Dockerfile for testing..."
                        cat > Dockerfile << 'EOF'
FROM openjdk:17-jdk-slim
WORKDIR /app
COPY target/*.jar app.jar
EXPOSE 8083
ENTRYPOINT ["java", "-jar", "app.jar"]
EOF
                        docker build -t ${DOCKER_IMAGE_NAME} .
                    fi
                    '''
                }
            }
        }
stage('Dependency Check') {
            steps {
                sh """
                    dependency-check.sh \
                        --scan . \
                        --format HTML \
                        --out dependency-check-report \
                        --noupdate \
                        || true
                """
            }
            post {
                always {
                    archiveArtifacts artifacts: 'dependency-check-report/*.html', allowEmptyArchive: true
                }
            }
        }
        stage('Trivy Scan') {
            steps {
                sh """
                    echo "Running Trivy vulnerability scan..."
                    mkdir -p trivy_reports
                    trivy image \
                        --timeout 15m \
                        --format template \
                        --template "@/usr/local/share/trivy/templates/html.tpl" \
                        -o trivy_reports/trivy-report.html \
                        testfoodfreezy \
                        || true
                """
            }
            post {
                always {
                    archiveArtifacts artifacts: 'trivy_reports/*.html', allowEmptyArchive: true
                }
            }
        }

        stage('OWASP Dependency-Check Vulnerabilities') {
            steps {
                script {
                    sh '''
                    echo "Running OWASP Dependency Check..."
                    '''
                    dependencyCheck additionalArguments: '''
                        --scan "./"
                        --enableExperimental
                        -f "ALL"
                        --prettyPrint
                        --out "./"
                        --project "DevSecOps_Project"
                        --failOnCVSS 0
                    ''', odcInstallation: 'DP-Check'
                    dependencyCheckPublisher pattern: 'dependency-check-report.xml'
                }
            }
            post {
                always {
                    archiveArtifacts artifacts: 'dependency-check-report.html', allowEmptyArchive: true
                }
            }
        }

        stage('Secrets Scan - Gitleaks') {
            steps {
                script {
                    sh """
                    echo "Running Gitleaks secrets scan..."
                    mkdir -p ${WORKSPACE}/secrets_reports
                    
                    docker run --rm -v ${WORKSPACE}:/code zricethezav/gitleaks:latest detect \
                        --source=/code \
                        --report-format=json \
                        --report-path=/code/secrets_reports/gitleaks-report.json \
                        --verbose \
                        --no-banner \
                        || echo "Gitleaks scan completed"
                    """
                }
            }
            post {
                always {
                    archiveArtifacts artifacts: 'secrets_reports/*.json', allowEmptyArchive: true
                }
            }
        }

       stage('Run WebApp') {
            steps {
                sh '''
                nohup java -jar target/*.jar > app.log 2>&1 &
                for i in {1..30}; do
                    if curl -s http://localhost:8083/  > /dev/null; then
                        echo "Application is up!"
                        exit 0
                    fi
                    echo "Waiting app to be ready..."
                    sleep 2
                done
                echo "Application failed to start!"
                exit 1
                '''
            }
        }


      stage('ZAP Scan') {
            steps {
                script {
                    sh "docker rm -f zap 2>/dev/null || true"

                    sh """
                        docker run -d --network host --name zap ghcr.io/zaproxy/zaproxy:stable sleep infinity
                    """

                    sh "docker exec zap mkdir -p /zap/wrk"

                    def zapExit = sh(
                        script: """
                            docker exec zap zap-full-scan.py \
                                -t http://localhost:8083 \
                                -r /zap/wrk/report.html
                        """,
                        returnStatus: true
                    )

                    echo "ZAP exit code: ${zapExit}"

                    sh "mkdir -p zap_reports"

                    sh """
                        if docker exec zap test -f /zap/wrk/report.html; then
                            docker cp zap:/zap/wrk/report.html zap_reports/report.html
                        else
                            echo '<h1>No ZAP report generated</h1>' > zap_reports/report.html
                        fi
                    """
                }
            }
            post {
                always {
                    archiveArtifacts artifacts: 'zap_reports/*.html', allowEmptyArchive: true
                    sh "docker rm -f zap || true"
                }
            }
        }


        stage('SonarQube Analysis') {
            steps {
                withSonarQubeEnv('sonar-server') {
                    sh """
                        mvn -B sonar:sonar \
                        -Dsonar.token=${SONAR_TOKEN}
                    """
                }
            }
        }


        stage('Quality Gate') {
            steps {
                timeout(time: 5, unit: 'MINUTES') {
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