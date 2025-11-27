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
                checkout scm
            }
        }

        stage('Setup Environment') {
            steps {
                sh '''
                echo "Setting up environment..."
                mkdir -p trivy_reports zap_reports secrets_reports
                
                # Install xmllint if not available
                if ! command -v xmllint &> /dev/null; then
                    echo "Installing xmllint..."
                    sudo apt-get update && sudo apt-get install -y libxml2-utils
                fi
                
                # Setup Trivy cache
                if [ ! -d "${TRIVY_CACHE_DIR}" ]; then
                    sudo mkdir -p ${TRIVY_CACHE_DIR}
                    sudo chown jenkins:jenkins ${TRIVY_CACHE_DIR}
                fi
                '''
            }
        }

        stage('Validate POM') {
            steps {
                sh '''
                echo "Validating POM file..."
                if [ -f pom.xml ]; then
                    # Simple validation without xmllint
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
                    semgrep --config=p/owasp-top-ten /src > semgrep-report.json || true
                '''
                archiveArtifacts artifacts: 'semgrep-report.json', allowEmptyArchive: true
            }
        }

        stage('Build + Unit Tests') {
            steps {
                sh '''
                echo "Building and running tests..."
                mvn clean compile test -DskipTests=false
                '''
            }
            post {
                success {
                    echo "Build and tests completed successfully"
                    sh 'echo "Test results: $(find target -name "*.txt" -o -name "*.xml" | grep -i test | head -5)"'
                }
                failure {
                    echo "Build or tests failed"
                }
            }
        }

        stage('SpotBugs Analysis') {
            steps {
                sh '''
                echo "Running SpotBugs analysis..."
                # Generate both XML and HTML reports
                mvn spotbugs:spotbugs spotbugs:check -Dspotbugs.failOnError=false
                mvn spotbugs:spotbugs -Dspotbugs.effort=Max -Dspotbugs.threshold=Low
                '''
            }
            post {
                always {
                    script {
                        // Archive whatever reports are available
                        sh '''
                        echo "Collecting SpotBugs reports..."
                        mkdir -p target/site || true
                        find target -name "spotbugs*" -type f | head -10
                        '''
                        archiveArtifacts artifacts: 'target/spotbugsXml.xml', allowEmptyArchive: true
                        archiveArtifacts artifacts: 'target/**/spotbugs*.xml', allowEmptyArchive: true
                        archiveArtifacts artifacts: 'target/**/spotbugs*.html', allowEmptyArchive: true
                    }
                }
            }
        }

        stage('Fast Dependency-Check') {
            steps {
                dependencyCheck additionalArguments: '''
                    --scan "./src/main/java"
                    --scan "./pom.xml"
                    --format "HTML" 
                    --format "JSON"
                    --prettyPrint
                    --out "."
                    --noupdate
                    --disableYarnAudit
                    --disableNodeAudit
                ''', odcInstallation: 'DP-Check'
                dependencyCheckPublisher pattern: 'dependency-check-report.xml'
            }
            post {
                always {
                    archiveArtifacts artifacts: 'dependency-check-report.html', allowEmptyArchive: true
                }
            }
        }

        stage('Secrets Scan') {
            steps {
                sh '''
                echo "Running secrets detection with Gitleaks..."
                docker run --rm -v $PWD:/code zricethezav/gitleaks:latest detect \
                    --source=/code \
                    --report-format=json \
                    --report-path=/code/secrets_reports/gitleaks-report.json \
                    --verbose || true
                '''
                archiveArtifacts artifacts: 'secrets_reports/*.json', allowEmptyArchive: true
            }
        }

        stage('Package Application') {
            steps {
                sh '''
                echo "Packaging application..."
                mvn package -DskipTests=true
                echo "Generated artifacts:"
                find target -name "*.war" -o -name "*.jar" | head -10
                '''
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
                
                # Use fast scan mode
                trivy image \
                    --cache-dir ${TRIVY_CACHE_DIR} \
                    --severity HIGH,CRITICAL \
                    --format template \
                    --template "@/usr/local/share/trivy/templates/html.tpl" \
                    -o trivy_reports/trivy-report.html \
                    testfoodfreezy || true
                
                echo "Trivy scan completed"
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'trivy_reports/*.html', allowEmptyArchive: true
                }
            }
        }

        stage('Run WebApp & ZAP Scan') {
            when {
                expression { currentBuild.resultIsBetterOrEqualTo('SUCCESS') }
            }
            steps {
                script {
                    // Start application
                    sh '''
                    JAR_FILE=$(find target -name "*.war" -o -name "*.jar" | grep -v sources | grep -v javadoc | head -1)
                    if [ -n "$JAR_FILE" ]; then
                        echo "Starting application: $JAR_FILE"
                        nohup java -jar "$JAR_FILE" > app.log 2>&1 &
                        echo $! > app.pid
                        
                        # Wait max 20 seconds for app to start
                        timeout 20s bash -c 'until curl -s http://localhost:8080/ >/dev/null; do sleep 2; done' || true
                    fi
                    '''
                    
                    // Quick ZAP Scan
                    sh '''
                    docker rm -f zap-scanner 2>/dev/null || true
                    timeout 60s docker run --rm \
                        -v $(pwd)/zap_reports:/zap/wrk:rw \
                        -e JAVA_OPTS="-Xmx1g" \
                        owasp/zap2docker-stable zap-baseline.py \
                        -t http://host.docker.internal:8080 \
                        -r -w /zap/wrk/zap-report.html \
                        -m 1 || true
                    '''
                }
            }
            post {
                always {
                    sh '''
                    # Stop application
                    [ -f app.pid ] && kill $(cat app.pid) 2>/dev/null || true
                    pkill -f "java -jar" 2>/dev/null || true
                    '''
                    archiveArtifacts artifacts: 'zap_reports/*.html', allowEmptyArchive: true
                    archiveArtifacts artifacts: 'app.log', allowEmptyArchive: true
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
                    mvn sonar:sonar \
                        -Dsonar.projectKey=devops_java \
                        -Dsonar.host.url=http://192.168.50.4:9000 \
                        -Dsonar.login=${SONAR_TOKEN} \
                        -Dsonar.coverage.jacoco.xmlReportPaths=target/site/jacoco/jacoco.xml \
                        -Dsonar.sourceEncoding=UTF-8
                    """
                }
            }
        }

        stage('Quality Gate') {
            when {
                expression { currentBuild.resultIsBetterOrEqualTo('SUCCESS') }
            }
            steps {
                timeout(time: 3, unit: 'MINUTES') {
                    waitForQualityGate abortPipeline: false
                }
            }
        }
    }

    post {
        always {
            script {
                // Collect and package reports
                sh '''
                echo "Collecting all reports..."
                mkdir -p reports
                   
                # Copy all available reports
                cp semgrep-report.json reports/ 2>/dev/null || echo "No Semgrep report"
                cp dependency-check-report.html reports/ 2>/dev/null || echo "No Dependency Check report"
                cp secrets_reports/*.json reports/ 2>/dev/null || echo "No Secrets report"
                cp zap_reports/*.html reports/ 2>/dev/null || echo "No ZAP report"
                cp trivy_reports/*.html reports/ 2>/dev/null || echo "No Trivy report"
                cp app.log reports/ 2>/dev/null || echo "No app log"
                
                # Copy SpotBugs reports - find any available
                find target -name "spotbugs*" -exec cp {} reports/ \\; 2>/dev/null || true
                find target -name "*spotbugs*" -exec cp {} reports/ \\; 2>/dev/null || true
                
                echo "Reports collected:"
                ls -la reports/ || echo "No reports directory"
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

                // Send notification
                emailext(
                    to: 'mekni.amin75@gmail.com',
                    subject: "🚀 Pipeline ${currentBuild.currentResult} - ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                    body: """
                        <h3>Security Pipeline Complete</h3>
                        <p><b>Status:</b> <span style="color: ${currentBuild.currentResult == 'SUCCESS' ? 'green' : 'orange'}">${currentBuild.currentResult}</span></p>
                        <p><b>Project:</b> ${env.JOB_NAME}</p>
                        <p><b>Build:</b> #${env.BUILD_NUMBER}</p>
                        <p><b>Duration:</b> ${currentBuild.durationString}</p>
                        <p><b>URL:</b> <a href="${env.BUILD_URL}">View Build</a></p>
                        <hr>
                        <p>All security reports are attached for review.</p>
                    """,
                    mimeType: 'text/html',
                    attachmentsPattern: 'reports.*',
                    attachLog: true
                )
            }
        }
    }
}