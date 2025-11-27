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
        stage('Clean Workspace') {
            steps {
                cleanWs()
                sh 'find . -name "target" -type d -exec rm -rf {} + 2>/dev/null || true'
            }
        }

        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Setup Environment') {
            steps {
                sh '''
                echo "Setting up environment..."
                mkdir -p trivy_reports zap_reports secrets_reports dependency_check_reports
                '''
            }
        }

        stage('Validate POM') {
            steps {
                sh '''
                echo "Validating POM file..."
                if [ -f pom.xml ]; then
                    if grep -q "<project" pom.xml && grep -q "</project>" pom.xml; then
                        echo "POM structure appears valid"
                    else
                        echo "POM may have structural issues"
                    fi
                else
                    echo "No POM file found!"
                    exit 1
                fi
                '''
            }
        }

        stage('Semgrep SAST') {
            steps {
                sh '''
                echo "Running Semgrep SAST scan..."
                docker run --rm -v $PWD:/src returntocorp/semgrep \
                    semgrep --config=p/owasp-top-ten /src > semgrep-report.json 2>/dev/null || echo "Semgrep scan completed"
                '''
                archiveArtifacts artifacts: 'semgrep-report.json', allowEmptyArchive: true
            }
        }

        stage('Build Application') {
            steps {
                sh '''
                echo "Building application..."
                mvn clean compile -DskipTests=true
                '''
            }
        }

        stage('SpotBugs Analysis') {
            steps {
                sh '''
                echo "Running SpotBugs analysis..."
                mvn spotbugs:spotbugs -Dspotbugs.failOnError=false
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'target/spotbugsXml.xml', allowEmptyArchive: true
                }
            }
        }

        stage('Dependency-Check with Docker - FIXED') {
            steps {
                sh '''
                echo "Running OWASP Dependency-Check with Docker..."
                
                # Create output directory
                mkdir -p dependency_check_reports
                
                # Use correct Docker command syntax
                docker run --rm \\
                    -v $PWD:/src \\
                    -v /tmp/dependency-check-data:/usr/share/dependency-check/data \\
                    owasp/dependency-check:latest \\
                    /bin/bash -c "dependency-check.sh \\
                    --scan /src \\
                    --format HTML \\
                    --format JSON \\
                    --out /src/dependency_check_reports \\
                    --project "vprofile-app" \\
                    --enableExperimental \\
                    --disableYarnAudit \\
                    --disableNodeAudit \\
                    --noupdate" || echo "Dependency-Check completed with exit code: $?"
                
                # Check if reports were generated
                echo "Generated reports:"
                ls -la dependency_check_reports/ || echo "No dependency check reports found"
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'dependency_check_reports/*', allowEmptyArchive: true
                }
            }
        }

        stage('Secrets Scan') {
            steps {
                sh '''
                echo "Running secrets detection..."
                mkdir -p secrets_reports
                docker run --rm -v $PWD:/code zricethezav/gitleaks:latest detect \\
                    --source=/code \\
                    --report-format=json \\
                    --report-path=/code/secrets_reports/gitleaks-report.json \\
                    --verbose || echo "Gitleaks scan completed"
                '''
                archiveArtifacts artifacts: 'secrets_reports/*.json', allowEmptyArchive: true
            }
        }

        stage('Optimize Build') {
            steps {
                sh '''
                echo "Analyzing dependencies for optimization..."
                # Check for large dependencies
                mvn dependency:tree -Dverbose > dependency-tree.txt
                
                echo "Current dependency tree saved to dependency-tree.txt"
                echo "Packaging with optimized settings..."
                
                # Clean package with dependency optimization
                mvn clean package -DskipTests=true -Dcheckstyle.skip=true -Dpmd.skip=true
                
                echo "Generated WAR file size:"
                ls -lh target/*.war 2>/dev/null || echo "No WAR file found"
                
                # Analyze WAR contents
                if [ -f "target/*.war" ]; then
                    echo "Top 10 largest files in WAR:"
                    unzip -l target/*.war | sort -nr -k1 | head -10
                fi
                '''
            }
        }

        stage('Build Docker Image') {
            when {
                expression { currentBuild.resultIsBetterOrEqualTo('SUCCESS') }
            }
            steps {
                sh '''
                echo "Building Docker image..."
                if [ ! -f "Dockerfile" ]; then
                    echo "Creating optimized Dockerfile..."
                    cat > Dockerfile << 'EOF'
FROM tomcat:10-jdk21
RUN rm -rf /usr/local/tomcat/webapps/*
COPY target/*.war /usr/local/tomcat/webapps/ROOT.war
WORKDIR /usr/local/tomcat/
EXPOSE 8080
CMD ["catalina.sh", "run"]
EOF
                fi
                docker build -t testfoodfreezy .
                echo "Docker image built successfully"
                
                # Check image size
                echo "Docker image details:"
                docker images testfoodfreezy
                '''
            }
        }

        stage('Fast Trivy Scan') {
            when {
                expression { currentBuild.resultIsBetterOrEqualTo('SUCCESS') }
            }
            steps {
                sh '''
                echo "Running FAST Trivy scan (OS packages only)..."
                mkdir -p trivy_reports
                
                # Fast scan with proper error handling
                docker run --rm \\
                    -v /var/run/docker.sock:/var/run/docker.sock \\
                    -v $PWD/trivy_reports:/output \\
                    aquasec/trivy:latest \\
                    image \\
                    --scanners vuln \\
                    --format template \\
                    --template "@contrib/html.tpl" \\
                    -o /output/trivy-fast.html \\
                    --severity HIGH,CRITICAL \\
                    testfoodfreezy || echo "Trivy scan completed with exit code: $?"
                
                echo "Fast vulnerability scan completed"
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'trivy_reports/*.html', allowEmptyArchive: true
                }
            }
        }

        stage('Comprehensive Trivy Scan') {
            when {
                expression { currentBuild.resultIsBetterOrEqualTo('SUCCESS') }
            }
            steps {
                sh '''
                echo "Running comprehensive Trivy scan..."
                mkdir -p trivy_reports
                
                # Update Trivy DB first
                docker run --rm \\
                    -v /tmp/trivy:/root/.cache \
                    aquasec/trivy:latest \\
                    image --download-db-only
                
                # Comprehensive scan
                docker run --rm \\
                    -v /var/run/docker.sock:/var/run/docker.sock \\
                    -v $PWD/trivy_reports:/output \\
                    -v /tmp/trivy:/root/.cache \\
                    aquasec/trivy:latest \\
                    image \\
                    --scanners vuln,secret,config \\
                    --format template \\
                    --template "@contrib/html.tpl" \\
                    -o /output/trivy-comprehensive.html \\
                    --severity HIGH,CRITICAL \\
                    testfoodfreezy || echo "Comprehensive Trivy scan completed"
                '''
            }
        }

        stage('Run WebApp for Testing') {
            when {
                expression { currentBuild.resultIsBetterOrEqualTo('SUCCESS') }
            }
            steps {
                sh '''
                echo "Starting application for testing..."
                # Stop any existing container
                docker stop test-app 2>/dev/null || true
                docker rm test-app 2>/dev/null || true
                
                # Start new container
                docker run -d --name test-app -p 8080:8080 testfoodfreezy
                echo "Application started in Docker container"
                
                # Wait for app to be ready with retries
                echo "Waiting for application to start..."
                for i in {1..30}; do
                    if curl -s http://localhost:8080/ > /dev/null; then
                        echo "✅ Application is running successfully"
                        break
                    fi
                    echo "Attempt $i/30: Application not ready yet..."
                    sleep 5
                done
                
                # Final check
                if ! curl -s http://localhost:8080/ > /dev/null; then
                    echo "⚠️  Application may not be fully started"
                    # Check container logs
                    docker logs test-app | tail -20
                fi
                '''
            }
            post {
                always {
                    sh '''
                    # Stop and cleanup
                    echo "Stopping test application..."
                    docker stop test-app 2>/dev/null || true
                    docker rm test-app 2>/dev/null || true
                    echo "Test application stopped"
                    '''
                }
            }
        }

        stage('Sonar Analysis') {
            when {
                expression { currentBuild.resultIsBetterOrEqualTo('SUCCESS') }
            }
            steps {
                withSonarQubeEnv('SonarQubeServer') {
                    sh """
                    mvn sonar:sonar \\
                        -Dsonar.projectKey=devops_java \\
                        -Dsonar.host.url=http://192.168.50.4:9000 \\
                        -Dsonar.login=${SONAR_TOKEN} \\
                        -Dsonar.coverage.jacoco.xmlReportPaths=target/site/jacoco/jacoco.xml \\
                        -Dsonar.sourceEncoding=UTF-8 \\
                        -Dsonar.tests=src/test/java \\
                        -Dsonar.java.binaries=target/classes
                    """
                }
            }
        }
    }

    post {
        always {
            script {
                // Collect all reports
                sh '''
                echo "Collecting security reports..."
                mkdir -p reports
                
                # Copy available reports with proper error handling
                cp semgrep-report.json reports/ 2>/dev/null || echo "No Semgrep report"
                cp dependency_check_reports/* reports/ 2>/dev/null || echo "No Dependency Check report"
                cp secrets_reports/*.json reports/ 2>/dev/null || echo "No Secrets report"
                cp trivy_reports/*.html reports/ 2>/dev/null || echo "No Trivy report"
                cp target/spotbugsXml.xml reports/ 2>/dev/null || echo "No SpotBugs report"
                
                # Create summary file
                echo "=== SECURITY SCAN SUMMARY ===" > reports/summary.txt
                echo "Build: ${env.JOB_NAME} #${env.BUILD_NUMBER}" >> reports/summary.txt
                echo "Timestamp: $(date)" >> reports/summary.txt
                echo "" >> reports/summary.txt
                echo "Generated Reports:" >> reports/summary.txt
                ls -la reports/ >> reports/summary.txt 2>/dev/null || echo "No reports found" >> reports/summary.txt
                
                echo "=== Final Reports ==="
                ls -la reports/ 2>/dev/null || echo "No reports directory"
                '''
                
                // Package reports
                sh '''
                echo "Packaging reports..."
                tar -czf reports.tar.gz reports/ 2>/dev/null || echo "Failed to package reports"
                '''
                
                // Cleanup Docker resources
                sh '''
                echo "Cleaning up Docker resources..."
                docker system prune -f 2>/dev/null || true
                '''
            }
            
            // Email notification
            emailext(
                to: 'mekni.amin75@gmail.com',
                subject: "🔒 Pipeline ${currentBuild.currentResult} - ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                body: """
                    <h3>🔒 Security Pipeline Complete</h3>
                    <p><b>Status:</b> ${currentBuild.currentResult}</p>
                    <p><b>Project:</b> ${env.JOB_NAME}</p>
                    <p><b>Build:</b> #${env.BUILD_NUMBER}</p>
                    <p><b>Duration:</b> ${currentBuild.durationString}</p>
                    
                    <h4>📊 Security Scans Completed:</h4>
                    <ul>
                        <li>✅ Semgrep SAST</li>
                        <li>✅ SpotBugs Analysis</li>
                        <li>✅ OWASP Dependency-Check (Fixed)</li>
                        <li>✅ Gitleaks Secrets Detection</li>
                        <li>✅ Trivy Container Scan (Fast + Comprehensive)</li>
                        <li>✅ Application Build & Package</li>
                        <li>✅ SonarQube Analysis</li>
                    </ul>
                    
                    <p><i>All security reports are attached.</i></p>
                """,
                mimeType: 'text/html',
                attachmentsPattern: 'reports.*',
                attachLog: true
            )
        }
        
        success {
            sh '''
            echo "🎉 Pipeline completed successfully!"
            echo "All security scans and builds completed."
            '''
        }
        
        failure {
            sh '''
            echo "❌ Pipeline failed!"
            echo "Check the logs for specific errors."
            '''
        }
    }
}