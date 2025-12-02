pipeline {
    agent any

    tools {
        maven 'MAVEN3'
        jdk 'JDK17'
    }

    environment {
        SONAR_TOKEN = credentials('sonar-token')
        NVD_API_KEY = credentials('nvd-api-key')  // Changed to credential ID, not the key itself
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
                    semgrep --config=p/owasp-top-ten /src > semgrep-report.json || true
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
                    echo "=== Checking for JAR file ==="
                    ls -la target/*.jar 2>/dev/null || echo "No JAR file found yet"
                '''
            }
        }

        stage('Build Docker Image') {
            steps {
                sh '''
                    echo "Building Docker image..."
                    docker build -f Dockerfile -t testfoodfreezy . || true
                '''
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
                script {
                    // First run Maven dependency check
                    sh 'mvn org.owasp:dependency-check-maven:check -DnvdApiKey=${NVD_API_KEY} || true'
                    
                    // Also run standalone dependency check
                    dependencyCheck additionalArguments: '''
                        --scan "./target"
                        --enableExperimental
                        -f "ALL"
                        --prettyPrint
                        --nvdApiKey ${NVD_API_KEY}
                    ''', odcInstallation: 'DP-Check'
                    
                    dependencyCheckPublisher pattern: 'dependency-check-report.xml'
                }
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
                # Kill any existing process on port 8089
                pkill -f "java.*8089" 2>/dev/null || true
                sleep 2
                
                # Check if jar file exists
                if [ ! -f target/*.jar ]; then
                    echo "ERROR: No JAR file found in target directory!"
                    echo "Listing target directory:"
                    ls -la target/ 2>/dev/null || echo "Target directory does not exist"
                    exit 1
                fi
                
                # Start the application
                echo "Starting application..."
                JAR_FILE=$(ls target/*.jar | head -1)
                nohup java -jar "$JAR_FILE" --server.port=8089 > app.log 2>&1 &
                APP_PID=$!
                echo "Application started with PID: $APP_PID"
                
                # Wait for application to start
                echo "Waiting for application to start..."
                for i in {1..30}; do
                    if curl -s http://localhost:8089/ > /dev/null 2>&1; then
                        echo "✓ Application is up and running!"
                        echo "Application health check:"
                        curl -s http://localhost:8089/ || true
                        exit 0
                    fi
                    echo "Attempt $i/30: Waiting for application..."
                    sleep 3
                done
                
                echo "✗ Application failed to start within 90 seconds"
                echo "=== Last 50 lines of app.log ==="
                tail -50 app.log
                
                # Kill the process if it's still running
                kill $APP_PID 2>/dev/null || true
                exit 1
                '''
            }
        }

        stage("ZAP Scan") {
            when {
                expression { 
                    try {
                        sh(script: 'curl -s http://localhost:8089/ > /dev/null 2>&1', returnStatus: true) == 0
                    } catch(Exception e) {
                        return false
                    }
                }
            }
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

                    // Don't fail the build on ZAP findings, just report them
                    if (zapExit == 1 || zapExit == 3) {
                        echo "ZAP scan completed with findings (exit code: ${zapExit})"
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
                    sh "mvn sonar:sonar -Dsonar.projectKey=devops_java -Dsonar.host.url=http://192.168.50.4:9000 -Dsonar.login=${SONAR_TOKEN} || true"
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
                def buildUser = currentBuild.getBuildCauses('hudson.model.Cause$UserIdCause')[0]?.userId ?: 'Triggered by SCM'
                def buildUrl = "${env.BUILD_URL}"

                sh '''
                    echo "=== Collecting Reports ==="
                    mkdir -p reports
                    
                    # Copy various reports if they exist
                    [ -f semgrep-report.json ] && cp semgrep-report.json reports/ || echo "No semgrep report"
                    
                    # SpotBugs reports
                    find . -name "spotbugsXml.xml" -exec cp {} reports/spotbugs-report.xml \; 2>/dev/null || echo "No SpotBugs XML report"
                    find . -name "spotbugs.html" -exec cp {} reports/spotbugs.html \; 2>/dev/null || echo "No SpotBugs HTML report"
                    
                    # Dependency Check reports
                    [ -f dependency-check-report.html ] && cp dependency-check-report.html reports/ || echo "No dependency check report"
                    [ -f target/dependency-check-report.html ] && cp target/dependency-check-report.html reports/dependency-check-report.html || true
                    
                    # Other reports
                    [ -f secrets_reports/gitleaks-report.json ] && cp secrets_reports/gitleaks-report.json reports/ || echo "No gitleaks report"
                    [ -f zap_reports/report.html ] && cp zap_reports/report.html reports/ || echo "No ZAP report"
                    [ -f trivy_reports/trivy-report.html ] && cp trivy_reports/trivy-report.html reports/ || echo "No Trivy report"
                    [ -f app.log ] && cp app.log reports/ || echo "No application log"
                    
                    echo "=== Reports collected ==="
                    ls -la reports/
                '''

                // Create archive of reports
                archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true

                // Create zip for email
                sh '''
                    if command -v zip >/dev/null 2>&1; then
                        zip -r security-reports.zip reports/ || true
                    else
                        tar -czf security-reports.tar.gz reports/ || true
                    fi
                '''

                // Send email notification
                emailext(
                    to: 'mekni.amin75@gmail.com',
                    subject: "🔒 Security Pipeline ${buildStatus} - ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                    body: """
                        <h2>Security Pipeline Execution Report</h2>
                        
                        <p><strong>Status:</strong> <span style="color: ${buildStatus == 'SUCCESS' ? 'green' : 'red'}; font-weight: bold;">${buildStatus}</span></p>
                        
                        <h3>Build Information</h3>
                        <ul>
                            <li><strong>Project:</strong> ${env.JOB_NAME}</li>
                            <li><strong>Build Number:</strong> #${env.BUILD_NUMBER}</li>
                            <li><strong>Triggered by:</strong> ${buildUser}</li>
                            <li><strong>Build URL:</strong> <a href="${buildUrl}">${buildUrl}</a></li>
                        </ul>
                        
                        <h3>Security Scans Performed</h3>
                        <ul>
                            <li>Semgrep SAST (Static Application Security Testing)</li>
                            <li>SpotBugs Static Code Analysis</li>
                            <li>OWASP Dependency Check</li>
                            <li>Secrets Detection with Gitleaks</li>
                            <li>Container Vulnerability Scan with Trivy</li>
                            <li>Dynamic Application Security Testing with OWASP ZAP</li>
                            <li>SonarQube Code Quality Analysis</li>
                        </ul>
                        
                        <p>All security reports are attached to this email as a zip file.</p>
                        
                        <hr>
                        <p style="color: #666; font-size: 12px;">
                            This is an automated message from Jenkins Security Pipeline.<br>
                            Build completed at: ${new Date().format("yyyy-MM-dd HH:mm:ss")}
                        </p>
                    """,
                    mimeType: 'text/html',
                    attachmentsPattern: 'security-reports.*',
                    attachLog: true
                )
            }
        }
        
        cleanup {
            // Clean up any running containers or processes
            sh '''
                echo "=== Cleaning up resources ==="
                # Kill any running Java processes from this build
                pkill -f "java.*FoodFrenzy" 2>/dev/null || true
                # Remove Docker containers
                docker rm -f zap 2>/dev/null || true
                # Remove Docker image
                docker rmi -f testfoodfreezy 2>/dev/null || true
                echo "Cleanup completed"
            '''
        }
    }
}