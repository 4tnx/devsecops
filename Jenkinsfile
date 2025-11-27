pipeline {
    agent any

    tools {
        maven 'MAVEN3'
        jdk 'JDK17'
    }

    environment {
        SONAR_TOKEN = credentials('sonar-token')
        TRIVY_CACHE_DIR = '/var/lib/jenkins/trivy-cache'
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

        stage('Setup Environment') {
            steps {
                sh '''
                echo "Setting up environment..."
                mkdir -p trivy_reports zap_reports secrets_reports
                
                # Create Trivy cache directory if it doesn't exist
                if [ ! -d "${TRIVY_CACHE_DIR}" ]; then
                    echo "Creating Trivy cache directory..."
                    sudo mkdir -p ${TRIVY_CACHE_DIR}
                    sudo chown jenkins:jenkins ${TRIVY_CACHE_DIR}
                fi
                
                # Download Trivy DB if not exists or older than 24 hours
                if [ ! -f "${TRIVY_CACHE_DIR}/db/metadata.json" ] || \\
                   find "${TRIVY_CACHE_DIR}/db/metadata.json" -mtime +1 | grep -q .; then
                    echo "Downloading Trivy database..."
                    trivy image --download-db-only --cache-dir ${TRIVY_CACHE_DIR}
                else
                    echo "Trivy database is up to date"
                fi
                '''
            }
        }

        stage('Validate POM') {
            steps {
                sh '''
                echo "Validating POM file..."
                if [ -f pom.xml ]; then
                    xmllint --noout pom.xml && echo "POM is valid XML" || echo "POM has XML syntax errors"
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
                echo "Running Semgrep…"
                docker run --rm -v $PWD:/src returntocorp/semgrep \
                    semgrep --config=p/owasp-top-ten /src > semgrep-report.json || true
                '''
                archiveArtifacts artifacts: 'semgrep-report.json', allowEmptyArchive: true
            }
        }

        stage('Build + Test') {
            steps {
                sh 'mvn clean compile -DskipTests=true'
            }
            post {
                success {
                    echo "Build completed successfully"
                }
                failure {
                    echo "Build failed - check POM configuration"
                }
            }
        }

        stage('Unit Tests') {
            steps {
                sh 'mvn test -DskipTests=false'
            }
        }

        stage('SpotBugs Analysis') {
            steps {
                sh 'mvn spotbugs:spotbugs -Dspotbugs.failOnError=false'
            }
            post {
                always {
                    archiveArtifacts artifacts: 'target/spotbugsXml.xml', allowEmptyArchive: true
                    archiveArtifacts artifacts: 'target/site/spotbugs.html', allowEmptyArchive: true
                }
            }
        }

        stage('OWASP Dependency-Check') {
            steps {
                dependencyCheck additionalArguments: '''
                    --scan "./"
                    --enableExperimental
                    -f "HTML"
                    --prettyPrint
                    --out "."
                ''', odcInstallation: 'DP-Check'
                dependencyCheckPublisher pattern: 'dependency-check-report.xml'
            }
            post {
                always {
                    archiveArtifacts artifacts: 'dependency-check-report.html', allowEmptyArchive: true
                }
            }
        }

        stage('Secrets Scan - Gitleaks') {
            steps {
                sh '''
                echo "Running secrets detection..."
                docker run --rm -v $PWD:/code zricethezav/gitleaks:latest detect \
                    --source=/code \
                    --report-format=json \
                    --report-path=/code/secrets_reports/gitleaks-report.json || true
                '''
                archiveArtifacts artifacts: 'secrets_reports/*.json', allowEmptyArchive: true
            }
        }

        stage('Package Application') {
            steps {
                sh 'mvn package -DskipTests=true'
            }
        }

        stage('Build Docker Image') {
            when {
                expression { currentBuild.resultIsBetterOrEqualTo('SUCCESS') && fileExists('Dockerfile') }
            }
            steps {
                sh '''
                echo "Building Docker image..."
                docker build -t testfoodfreezy .
                '''
            }
        }

        stage('Trivy Scan') {
            when {
                expression { currentBuild.resultIsBetterOrEqualTo('SUCCESS') && fileExists('Dockerfile') }
            }
            steps {
                sh '''
                echo "Running Trivy vulnerability scan..."
                
                # Run Trivy scan with cache
                trivy image \
                    --cache-dir ${TRIVY_CACHE_DIR} \
                    --format template \
                    --template "@/usr/local/share/trivy/templates/html.tpl" \
                    -o trivy_reports/trivy-report.html \
                    testfoodfreezy || true
                
                echo "Trivy scan completed. Report saved to trivy_reports/trivy-report.html"
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'trivy_reports/*.html', allowEmptyArchive: true
                }
            }
        }

        stage('Run WebApp') {
            when {
                expression { currentBuild.resultIsBetterOrEqualTo('SUCCESS') }
            }
            steps {
                sh '''
                # Kill any existing process on port 8080
                pkill -f "java -jar target/*.jar" || true
                sleep 2
                
                # Find the built JAR file
                JAR_FILE=$(find target -name "*.jar" -not -name "*sources*" -not -name "*javadoc*" | head -1)
                
                if [ -n "$JAR_FILE" ] && [ -f "$JAR_FILE" ]; then
                    echo "Starting application: $JAR_FILE"
                    nohup java -jar "$JAR_FILE" > app.log 2>&1 &
                    echo $! > app.pid
                    
                    # Wait for application to start
                    for i in {1..30}; do
                        if curl -s http://localhost:8080/ > /dev/null; then
                            echo "Application is up and running!"
                            break
                        fi
                        echo "Waiting for app to be ready... ($i/30)"
                        sleep 2
                    done
                else
                    echo "No JAR file found to execute"
                fi
                '''
            }
        }

        stage('ZAP Scan') {
            when {
                expression { currentBuild.resultIsBetterOrEqualTo('SUCCESS') }
            }
            steps {
                script {
                    // Ensure ZAP container is clean
                    sh "docker rm -f zap-scanner 2>/dev/null || true"
                    
                    // Run ZAP container
                    sh """
                    docker run -u zap -d --name zap-scanner \
                        -v ${WORKSPACE}/zap_reports:/zap/wrk:rw \
                        -p 8081:8080 ghcr.io/zaproxy/zaproxy:stable zap.sh \
                        -daemon -host 0.0.0.0 -port 8080 -config api.disablekey=true
                    """
                    
                    // Wait for ZAP to start
                    sleep 30
                    
                    // Run the scan
                    sh """
                    docker exec zap-scanner zap-full-scan.py \
                        -t http://host.docker.internal:8080 \
                        -r /zap/wrk/zap-report.html \
                        -I || true
                    """
                }
            }
            post {
                always {
                    archiveArtifacts artifacts: 'zap_reports/*.html', allowEmptyArchive: true
                    sh "docker rm -f zap-scanner || true"
                    // Stop the application
                    sh 'pkill -F app.pid 2>/dev/null || true'
                    sh 'pkill -f "java -jar target/*.jar" 2>/dev/null || true'
                }
            }
        }

        stage('Sonar Analysis') {
            when {
                expression { currentBuild.resultIsBetterOrEqualTo('SUCCESS') }
            }
            steps {
                withSonarQubeEnv('SonarQubeServer') {
                    sh "mvn sonar:sonar \
                        -Dsonar.projectKey=devops_java \
                        -Dsonar.host.url=http://192.168.50.4:9000 \
                        -Dsonar.login=${SONAR_TOKEN} \
                        -Dsonar.coverage.jacoco.xmlReportPaths=target/site/jacoco/jacoco.xml"
                }
            }
        }

        stage('Quality Gate') {
            when {
                expression { currentBuild.resultIsBetterOrEqualTo('SUCCESS') }
            }
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
                // Collect all reports
                sh '''
                    mkdir -p reports
                    cp semgrep-report.json reports/ 2>/dev/null || true
                    cp target/spotbugsXml.xml reports/ 2>/dev/null || true
                    cp target/site/spotbugs.html reports/ 2>/dev/null || true
                    cp dependency-check-report.html reports/ 2>/dev/null || true
                    cp secrets_reports/*.json reports/ 2>/dev/null || true
                    cp zap_reports/*.html reports/ 2>/dev/null || true
                    cp trivy_reports/*.html reports/ 2>/dev/null || true
                    cp app.log reports/ 2>/dev/null || true
                '''

                // Package reports
                sh '''
                    if command -v zip >/dev/null 2>&1; then
                        zip -r reports.zip reports/
                    else
                        tar -czf reports.tar.gz reports/
                    fi
                '''

                // Cleanup
                sh 'pkill -f "java -jar" 2>/dev/null || true'
                sh 'rm -f app.pid 2>/dev/null || true'

                // Send email notification
                emailext(
                    to: 'mekni.amin75@gmail.com',
                    subject: "📊 Pipeline ${currentBuild.currentResult} - ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                    body: """
                        <h3>Pipeline Execution Result</h3>
                        <p><b>Status:</b> <span style="color: ${currentBuild.currentResult == 'SUCCESS' ? 'green' : 'red'}">${currentBuild.currentResult}</span></p>
                        <p><b>Project:</b> ${env.JOB_NAME}</p>
                        <p><b>Build:</b> #${env.BUILD_NUMBER}</p>
                        <p><b>URL:</b> <a href="${env.BUILD_URL}">${env.BUILD_URL}</a></p>
                        <hr>
                        <p>All security reports are attached.</p>
                    """,
                    mimeType: 'text/html',
                    attachmentsPattern: 'reports.*',
                    attachLog: true
                )
            }
        }
    }
}