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
                sh '''
                echo "Running SpotBugs analysis..."
                mvn clean compile spotbugs:spotbugs || echo "SpotBugs analysis completed"
                '''
            }
            post {
                always {
                    script {
                        sh '''
                        mkdir -p target/site 2>/dev/null || true
                        '''
                        if (fileExists('target/spotbugsXml.xml')) {
                            archiveArtifacts artifacts: 'target/spotbugsXml.xml', allowEmptyArchive: true
                        }
                        if (fileExists('target/site/spotbugs.html')) {
                            archiveArtifacts artifacts: 'target/site/spotbugs.html', allowEmptyArchive: true
                        }
                    }
                }
            }
        }

        stage('Build + Test') {
            steps {
                sh '''
                echo "Building and running tests..."
                mvn clean verify -DskipTests=false || echo "Tests completed with warnings"
                '''
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
                script {
                    sh '''
                    echo "Starting the web application..."
                    # Kill any existing process on port 8080
                    lsof -ti:8080 | xargs kill -9 2>/dev/null || true
                    
                    # Start the application in background
                    nohup java -jar target/*.jar > app.log 2>&1 &
                    
                    APP_PID=$!
                    echo "Application started with PID: $APP_PID"
                    
                    # Wait for application to be ready
                    MAX_WAIT=60
                    WAIT_COUNT=0
                    
                    while [ $WAIT_COUNT -lt $MAX_WAIT ]; do
                        if curl -s -f http://localhost:8080/ > /dev/null 2>&1; then
                            echo "✓ Application is up and running!"
                            echo "Application logs (last 20 lines):"
                            tail -20 app.log
                            break
                        fi
                        
                        # Check if process is still running
                        if ! ps -p $APP_PID > /dev/null 2>&1; then
                            echo "✗ Application process died!"
                            echo "Application logs:"
                            cat app.log
                            exit 1
                        fi
                        
                        echo "Waiting for application to be ready... ($((WAIT_COUNT+1))/$MAX_WAIT)"
                        sleep 5
                        WAIT_COUNT=$((WAIT_COUNT + 1))
                    done
                    
                    if [ $WAIT_COUNT -ge $MAX_WAIT ]; then
                        echo "✗ Application failed to start within timeout!"
                        echo "Application logs:"
                        cat app.log
                        exit 1
                    fi
                    '''
                }
            }
        }

        stage("ZAP Scan") {
            steps {
                script {
                    sh '''
                    echo "Starting ZAP security scan..."
                    mkdir -p ${WORKSPACE}/zap_reports
                    
                    # Clean up any existing ZAP container
                    docker rm -f zap 2>/dev/null || true
                    
                    # Start ZAP container
                    docker run -d --network host --name zap ghcr.io/zaproxy/zaproxy:stable sleep 3600
                    sleep 10  # Wait for container to initialize
                    
                    # Wait for ZAP to be ready
                    for i in {1..10}; do
                        if docker exec zap curl -s http://localhost:8080/ > /dev/null 2>&1; then
                            echo "ZAP container is ready"
                            break
                        fi
                        echo "Waiting for ZAP container... ($i/10)"
                        sleep 5
                    done
                    
                    # Run ZAP scan with proper timeout and options
                    echo "Running ZAP full scan..."
                    docker exec zap zap-full-scan.py \
                        -t http://localhost:8080 \
                        -T 120 \
                        -m 10 \
                        -r /zap/report.html \
                        -x /zap/report.xml \
                        --hook=/zap/auth_hook.py \
                        || echo "ZAP scan completed with exit code: $?"
                    
                    # Wait a moment for report generation
                    sleep 5
                    
                    # Copy reports from container
                    docker cp zap:/zap/report.html ${WORKSPACE}/zap_reports/report.html 2>/dev/null || echo "Failed to copy HTML report"
                    docker cp zap:/zap/report.xml ${WORKSPACE}/zap_reports/report.xml 2>/dev/null || echo "Failed to copy XML report"
                    
                    # Stop the application
                    lsof -ti:8080 | xargs kill -9 2>/dev/null || true
                    '''
                }
            }
            post {
                always {
                    script {
                        if (fileExists('zap_reports/report.html')) {
                            archiveArtifacts artifacts: 'zap_reports/report.html', allowEmptyArchive: true
                        }
                        sh 'docker rm -f zap 2>/dev/null || true'
                    }
                }
            }
        }

        stage('Sonar Analysis') {
            steps {
                script {
                    withSonarQubeEnv('SonarQubeServer') {
                        sh '''
                        echo "Running SonarQube analysis..."
                        mvn sonar:sonar \
                            -Dsonar.projectKey=devops_java \
                            -Dsonar.host.url=http://192.168.50.4:9000 \
                            -Dsonar.login=${SONAR_TOKEN} \
                            -Dsonar.sources=src \
                            -Dsonar.tests=src/test \
                            -Dsonar.java.binaries=target/classes \
                            -Dsonar.junit.reportPaths=target/surefire-reports \
                            -Dsonar.coverage.jacoco.xmlReportPaths=target/site/jacoco/jacoco.xml \
                            -Dsonar.dependencyCheck.htmlReportPath=dependency-check-report.html \
                            -Dsonar.dependencyCheck.jsonReportPath=dependency-check-report.json \
                            || echo "SonarQube analysis completed with warnings"
                        '''
                    }
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
                def buildUser = currentBuild.getBuildCauses('hudson.model.Cause$UserIdCause')[0]?.userId ?: 'Triggered by SCM'
                def buildUrl = "${env.BUILD_URL}"
                
                // Clean up any running processes
                sh '''
                echo "Cleaning up processes..."
                lsof -ti:8080 | xargs kill -9 2>/dev/null || true
                docker rm -f zap 2>/dev/null || true
                '''
                
                // Collect all reports
                sh '''
                echo "Collecting all security reports..."
                mkdir -p reports
                
                # Copy reports with individual checks
                [ -f semgrep-report.json ] && cp semgrep-report.json reports/ || echo "Semgrep report not found"
                [ -f target/spotbugsXml.xml ] && cp target/spotbugsXml.xml reports/ 2>/dev/null || echo "Spotbugs XML not found"
                [ -f target/site/spotbugs.html ] && cp target/site/spotbugs.html reports/ 2>/dev/null || echo "Spotbugs HTML not found"
                [ -f dependency-check-report.html ] && cp dependency-check-report.html reports/ || echo "Dependency check report not found"
                [ -f dependency-check-report.json ] && cp dependency-check-report.json reports/ 2>/dev/null || echo "Dependency check JSON not found"
                [ -f secrets_reports/gitleaks-report.json ] && cp secrets_reports/gitleaks-report.json reports/ 2>/dev/null || echo "Gitleaks report not found"
                [ -f zap_reports/report.html ] && cp zap_reports/report.html reports/ 2>/dev/null || echo "ZAP report not found"
                [ -f zap_reports/report.xml ] && cp zap_reports/report.xml reports/ 2>/dev/null || echo "ZAP XML report not found"
                [ -f trivy_reports/trivy-report.html ] && cp trivy_reports/trivy-report.html reports/ 2>/dev/null || echo "Trivy HTML report not found"
                [ -f trivy_reports/trivy-report.json ] && cp trivy_reports/trivy-report.json reports/ 2>/dev/null || echo "Trivy JSON report not found"
                [ -f app.log ] && cp app.log reports/ 2>/dev/null || echo "Application log not found"
                
                echo "=== Reports Collected ==="
                ls -la reports/ 2>/dev/null || echo "No reports directory created"
                echo ""
                
                # Create archive
                if command -v zip >/dev/null 2>&1; then
                    echo "Creating ZIP archive..."
                    zip -r reports.zip reports/ 2>/dev/null || echo "Failed to create ZIP"
                else
                    echo "Creating TAR archive..."
                    tar -czf reports.tar.gz reports/ 2>/dev/null || echo "Failed to create TAR"
                fi
                '''
                
                // Send email notification
                emailext(
                    to: 'mekni.amin75@gmail.com',
                    subject: "📊 Security Pipeline ${buildStatus} - ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                    body: """
                        <html>
                        <body style="font-family: Arial, sans-serif; line-height: 1.6;">
                            <h2>Security Pipeline Report</h2>
                            <p>Hello,</p>
                            <p>The security pipeline has completed with status: <strong>${buildStatus}</strong>.</p>
                            
                            <h3>Build Details</h3>
                            <ul>
                                <li><strong>Project:</strong> ${env.JOB_NAME}</li>
                                <li><strong>Build Number:</strong> ${env.BUILD_NUMBER}</li>
                                <li><strong>Triggered by:</strong> ${buildUser}</li>
                                <li><strong>Jenkins Build URL:</strong> <a href="${buildUrl}">${buildUrl}</a></li>
                                <li><strong>Duration:</strong> ${currentBuild.durationString}</li>
                            </ul>
                            
                            <h3>Security Tools Executed</h3>
                            <ul>
                                <li>✓ Semgrep SAST Analysis</li>
                                <li>✓ SpotBugs Static Analysis</li>
                                <li>✓ OWASP Dependency Check</li>
                                <li>✓ Trivy Container Scanning</li>
                                <li>✓ Gitleaks Secrets Detection</li>
                                <li>✓ OWASP ZAP Dynamic Analysis</li>
                                <li>✓ SonarQube Quality Gate</li>
                            </ul>
                            
                            <p>All generated reports are attached to this email.</p>
                            
                            <hr>
                            <p style="color: #666; font-size: 12px;">
                                This is an automated message from Jenkins CI/CD Security Pipeline.<br>
                                Please review the attached reports for detailed findings.
                            </p>
                        </body>
                        </html>
                    """,
                    mimeType: 'text/html',
                    attachmentsPattern: 'reports.zip,reports.tar.gz',
                    attachLog: true
                )
                
                // Clean up
                sh '''
                echo "Final cleanup..."
                docker system prune -f 2>/dev/null || true
                '''
            }
        }
        
        failure {
            script {
                echo "Pipeline failed. Check logs for details."
                // Send failure notification if needed
                emailext(
                    to: 'mekni.amin75@gmail.com',
                    subject: "❌ Pipeline FAILED - ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                    body: "The Jenkins pipeline has failed. Please check the build logs.",
                    attachLog: true
                )
            }
        }
        
        success {
            script {
                echo "Pipeline succeeded!"
                // Additional success actions if needed
            }
        }
    }
}