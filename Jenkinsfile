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

        stage('SpotBugs Analysis') {
            steps {
                sh 'mvn clean compile spotbugs:check || true'
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
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
EOF
                        docker build -t ${DOCKER_IMAGE_NAME} .
                    fi
                    '''
                }
            }
        }

        stage('Trivy Scan') {
            steps {
                script {
                    sh '''
                    echo "Running Trivy vulnerability scan..."
                    mkdir -p trivy_reports
                    # Clean Trivy cache if needed
                    trivy image --clear-cache 2>/dev/null || true
                    
                    # Run Trivy with increased timeout and limited scanners for speed
                    trivy image \
                        --timeout 20m \
                        --scanners vuln \
                        --severity HIGH,CRITICAL \
                        --format template \
                        --template "@/usr/local/share/trivy/templates/html.tpl" \
                        -o trivy_reports/trivy-report.html \
                        ${DOCKER_IMAGE_NAME} \
                        || echo "Trivy scan completed with exit code: $?"
                    
                    # Also generate a JSON report for SonarQube integration
                    trivy image --format json -o trivy_reports/trivy-report.json ${DOCKER_IMAGE_NAME} || true
                    '''
                }
            }
            post {
                always {
                    script {
                        if (fileExists('trivy_reports/trivy-report.html')) {
                            archiveArtifacts artifacts: 'trivy_reports/trivy-report.html', allowEmptyArchive: true
                        }
                    }
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
                    if curl -s http://localhost:8080/  > /dev/null; then
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

      stage("ZAP Scan") {
    steps {
        script {
            sh "docker rm -f zap 2>/dev/null || true"

            // Run ZAP in background
            sh """
                docker run -d --network host --name zap ghcr.io/zaproxy/zaproxy:stable sleep infinity
            """

            // Create working directory
            sh "docker exec zap mkdir -p /zap/wrk"

            // Run scan + generate report in correct folder
            def zapExit = sh(
                script: """
                    docker exec zap zap-full-scan.py \
                        -t http://localhost:8080 \
                        -r /zap/wrk/report.html
                """,
                returnStatus: true
            )

            // Copy report safely
            sh "mkdir -p ${WORKSPACE}/zap_reports"
            sh """
                if docker exec zap test -f /zap/wrk/report.html; then
                    docker cp zap:/zap/wrk/report.html ${WORKSPACE}/zap_reports/report.html
                else
                    echo 'ZAP report not found!'
                    echo '<h1>No ZAP report generated</h1>' > ${WORKSPACE}/zap_reports/report.html
                fi
            """

            echo "ZAP scan finished with exit code: ${zapExit}"

            // Exit codes 1,3 indicate issues found, but still generate report
            if (zapExit == 1 || zapExit == 3) {
                echo "ZAP reported findings—continuing."
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
                script {
                    timeout(time: 5, unit: 'MINUTES') {
                        waitForQualityGate abortPipeline: false
                    }
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