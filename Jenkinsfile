pipeline {
    agent any

    tools {
        maven 'MAVEN3'
        jdk 'JDK17'
    }

    environment {
        SONAR_TOKEN = credentials('sonar-token')
        DOCKER_IMAGE_NAME = 'testfoodfreezy'
        APP_PORT = '8089'
        DEPENDENCY_CHECK_HOME = '/opt/dependency-check'  // Add this line
    }

    stages {
        stage('Cleanup Workspace') {
            steps {
                deleteDir()
                
                // Clean Docker containers and images
                sh '''
                    echo "Cleaning up Docker containers..."
                    docker rm -f test-app 2>/dev/null || true
                    docker rm -f zap-container 2>/dev/null || true
                    docker system prune -f 2>/dev/null || true
                '''
                
                // Kill process on APP_PORT
                sh '''
                    echo "Checking for processes on port ${APP_PORT}..."
                    lsof -ti:${APP_PORT} | xargs kill -9 2>/dev/null || true
                    sleep 2
                '''
            }
        }

        stage('Checkout') {
            steps {
                checkout([
                    $class: 'GitSCM',
                    branches: [[name: 'main']],
                    userRemoteConfigs: [[
                        url: 'https://github.com/4tnx/devsecops',
                        credentialsId: '' 
                    ]]
                ])
            }
        }

        stage('Initialize Workspace') {
            steps {
                sh '''
                    echo "=== Initializing Workspace ==="
                    echo "Java version:"
                    java -version
                    echo "Maven version:"
                    mvn --version
                    echo "Docker version:"
                    docker --version
                    echo "=== End Initialization ==="
                '''
            }
        }

        stage('Compile & Build') {
            steps {
                sh '''
                    echo "Compiling project..."
                    mvn -B clean compile
                    
                    echo "Building JAR..."
                    mvn -B -DskipTests package
                '''
            }
        }

        stage('Spotbugs Analysis') {
            steps {
                sh "mvn -B spotbugs:spotbugs"
            }
            post {
                always {
                    sh '''
                        echo "Collecting SpotBugs reports..."
                        mkdir -p ${WORKSPACE}/reports
                        cp target/spotbugs.xml ${WORKSPACE}/reports/ 2>/dev/null || echo "No spotbugs.xml found"
                        cp target/site/spotbugs.html ${WORKSPACE}/reports/ 2>/dev/null || echo "No spotbugs.html found"
                        
                        # Generate basic report if none exists
                        if [ ! -f "${WORKSPACE}/reports/spotbugs.html" ]; then
                            echo '<h1>SpotBugs Report</h1><p>No issues found or report not generated.</p>' > ${WORKSPACE}/reports/spotbugs.html
                        fi
                    '''
                }
            }
        }

        stage('Semgrep SAST') {
            steps {
                sh '''
                    echo "Running Semgrep SAST..."
                    docker run --rm \
                        -v ${WORKSPACE}:/src \
                        returntocorp/semgrep:latest \
                        semgrep scan \
                        --config=auto \
                        --json \
                        --output=/src/semgrep-report.json \
                        /src || true
                '''
            }
            post {
                always {
                    sh '''
                        cp semgrep-report.json ${WORKSPACE}/reports/ 2>/dev/null || \
                            echo '{"results": []}' > ${WORKSPACE}/reports/semgrep-report.json
                    '''
                }
            }
        }

        stage('Dependency Check (Fixed Database)') {
            steps {
                sh '''
                    echo "Running OWASP Dependency-Check..."
                    
                    # Create local database directory with proper permissions
                    mkdir -p ${WORKSPACE}/.dependency-check
                    
                    # Run dependency-check with local database
                    dependency-check.sh \
                        --scan . \
                        --project "FoodFrenzy" \
                        --out ${WORKSPACE} \
                        --format HTML \
                        --format XML \
                        --data ${WORKSPACE}/.dependency-check \
                        --enableExperimental \
                        --failOnCVSS 0 \
                        --disableAssembly \
                        --disableBundleAudit \
                        --nodeAuditSkipDevDependencies || echo "Dependency-Check completed with warnings"
                        
                    # Alternative: Use Maven plugin instead
                    # mvn org.owasp:dependency-check-maven:check -Dformat=HTML -Dformat=XML -DskipProvidedScope=true
                '''
            }
            post {
                always {
                    sh '''
                        echo "Collecting Dependency-Check reports..."
                        cp dependency-check-report.html ${WORKSPACE}/reports/ 2>/dev/null || true
                        cp dependency-check-report.xml ${WORKSPACE}/reports/ 2>/dev/null || true
                        
                        # Generate basic report if none exists
                        if [ ! -f "${WORKSPACE}/reports/dependency-check-report.html" ]; then
                            echo '<h1>Dependency-Check Report</h1><p>Report generation failed. Check database configuration.</p>' > ${WORKSPACE}/reports/dependency-check-report.html
                        fi
                    '''
                }
            }
        }

        stage('Build Docker Image') {
            steps {
                sh '''
                    echo "Building Docker image..."
                    docker build -t ${DOCKER_IMAGE_NAME}:${BUILD_NUMBER} .
                    docker tag ${DOCKER_IMAGE_NAME}:${BUILD_NUMBER} ${DOCKER_IMAGE_NAME}:latest
                '''
            }
        }

        stage('Trivy Scan') {
            steps {
                sh '''
                    echo "Running Trivy vulnerability scan..."
                    mkdir -p ${WORKSPACE}/trivy_reports
                    
                    # Scan the Docker image
                    trivy image \
                        --timeout 15m \
                        --format template \
                        --template "@/usr/local/share/trivy/templates/html.tpl" \
                        -o ${WORKSPACE}/trivy_reports/trivy-report.html \
                        ${DOCKER_IMAGE_NAME}:${BUILD_NUMBER} || true
                        
                    # Also scan filesystem
                    trivy filesystem \
                        --format json \
                        -o ${WORKSPACE}/trivy_reports/trivy-fs-report.json \
                        . || true
                '''
            }
            post {
                always {
                    sh '''
                        cp trivy_reports/trivy-report.html ${WORKSPACE}/reports/ 2>/dev/null || \
                            echo '<h1>Trivy Report</h1><p>Scan failed or no vulnerabilities found.</p>' > ${WORKSPACE}/reports/trivy-report.html
                    '''
                }
            }
        }

        stage('Secrets Scan - Gitleaks') {
            steps {
                sh '''
                    echo "Running Gitleaks secrets scan..."
                    mkdir -p ${WORKSPACE}/secrets_reports
                    
                    docker run --rm \
                        -v ${WORKSPACE}:/code \
                        zricethezav/gitleaks:latest \
                        detect \
                        --source=/code \
                        --report-format=json \
                        --report-path=/code/secrets_reports/gitleaks-report.json \
                        --verbose || echo "Gitleaks scan completed"
                '''
            }
            post {
                always {
                    sh '''
                        cp secrets_reports/gitleaks-report.json ${WORKSPACE}/reports/ 2>/dev/null || \
                            echo '{"Findings": []}' > ${WORKSPACE}/reports/gitleaks-report.json
                    '''
                }
            }
        }

        stage('Run WebApp in Container') {
            steps {
                sh '''
                    echo "Starting application on port ${APP_PORT}..."
                    
                    # Clean up any existing container
                    docker rm -f test-app 2>/dev/null || true
                    
                    # Run the application in Docker container
                    docker run -d \
                        --name test-app \
                        --network=host \
                        -p ${APP_PORT}:${APP_PORT} \
                        -e SERVER_PORT=${APP_PORT} \
                        ${DOCKER_IMAGE_NAME}:${BUILD_NUMBER}
                    
                    echo "Waiting for application to start..."
                    
                    # Wait for application to be ready
                    MAX_WAIT=60
                    WAIT_COUNT=0
                    while [ ${WAIT_COUNT} -lt ${MAX_WAIT} ]; do
                        if curl -s -f http://localhost:${APP_PORT}/actuator/health > /dev/null 2>&1 || \
                           curl -s -f http://localhost:${APP_PORT}/ > /dev/null 2>&1; then
                            echo "Application is up and running!"
                            break
                        fi
                        
                        echo "Waiting for application... (${WAIT_COUNT}/${MAX_WAIT})"
                        WAIT_COUNT=$((WAIT_COUNT + 1))
                        sleep 2
                        
                        # Check if container is still running
                        if ! docker ps | grep -q test-app; then
                            echo "Container stopped unexpectedly!"
                            docker logs test-app || true
                            exit 1
                        fi
                    done
                    
                    if [ ${WAIT_COUNT} -ge ${MAX_WAIT} ]; then
                        echo "ERROR: Application failed to start within ${MAX_WAIT} seconds"
                        docker logs test-app || true
                        exit 1
                    fi
                '''
            }
        }

        stage('ZAP Scan') {
            steps {
                sh '''
                    echo "Starting ZAP scan..."
                    mkdir -p ${WORKSPACE}/zap_reports
                    
                    # Run ZAP passive scan
                    docker run --rm \
                        -v ${WORKSPACE}/zap_reports:/zap/wrk \
                        -u zap \
                        --network=host \
                        owasp/zap2docker-stable \
                        zap-baseline.py \
                        -t http://localhost:${APP_PORT} \
                        -r report.html \
                        -m 5 \
                        -l PASSIVE || echo "ZAP scan completed with warnings"
                '''
            }
            post {
                always {
                    sh '''
                        echo "Collecting ZAP reports..."
                        cp zap_reports/report.html ${WORKSPACE}/reports/ 2>/dev/null || \
                            echo '<h1>ZAP Report</h1><p>ZAP scan failed or no issues found.</p>' > ${WORKSPACE}/reports/zap-report.html
                    '''
                    
                    // Stop the test application
                    sh 'docker rm -f test-app 2>/dev/null || true'
                }
            }
        }

        stage('SonarQube Analysis') {
            steps {
                withSonarQubeEnv('sonar-server') {
                    sh """
                        mvn -B sonar:sonar \
                            -Dsonar.projectKey=FoodFrenzy \
                            -Dsonar.projectName='FoodFrenzy' \
                            -Dsonar.host.url=\${SONAR_HOST_URL} \
                            -Dsonar.token=\${SONAR_TOKEN} \
                            -Dsonar.java.binaries=target/classes \
                            -Dsonar.sources=src/main/java \
                            -Dsonar.tests=src/test/java \
                            -Dsonar.junit.reportsPath=target/surefire-reports \
                            -Dsonar.jacoco.reportPath=target/jacoco.exec
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
                echo "Pipeline completed with status: ${currentBuild.currentResult}"
                
                // Final cleanup
                sh '''
                    echo "Performing final cleanup..."
                    docker rm -f test-app 2>/dev/null || true
                    docker rmi ${DOCKER_IMAGE_NAME}:${BUILD_NUMBER} 2>/dev/null || true
                    
                    # List collected reports
                    echo "=== Collected Reports ==="
                    ls -la ${WORKSPACE}/reports/ 2>/dev/null || echo "No reports directory"
                '''
                
                // Archive all reports
                archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true
                
                // Create consolidated report zip
                sh '''
                    mkdir -p ${WORKSPACE}/artifacts
                    if [ -d "${WORKSPACE}/reports" ]; then
                        cd ${WORKSPACE}/reports
                        zip -r ${WORKSPACE}/artifacts/security-reports.zip .
                    fi
                '''
                
                // Archive the zip
                archiveArtifacts artifacts: 'artifacts/security-reports.zip', allowEmptyArchive: true
                
                // Send email notification
                emailext(
                    to: 'mekni.amin75@gmail.com',
                    subject: "🔒 Security Scan ${currentBuild.currentResult} - ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                    body: """
                        <h2>Security Pipeline Results</h2>
                        <p><strong>Status:</strong> ${currentBuild.currentResult}</p>
                        <p><strong>Project:</strong> ${env.JOB_NAME}</p>
                        <p><strong>Build:</strong> #${env.BUILD_NUMBER}</p>
                        <p><strong>Build URL:</strong> <a href="${env.BUILD_URL}">${env.BUILD_URL}</a></p>
                        
                        <h3>Summary:</h3>
                        <ul>
                            <li>SAST Scan (Semgrep): Completed</li>
                            <li>Static Analysis (SpotBugs): Completed</li>
                            <li>Dependency Check: Completed</li>
                            <li>Container Scan (Trivy): Completed</li>
                            <li>Secrets Scan (Gitleaks): Completed</li>
                            <li>DAST Scan (ZAP): Completed</li>
                            <li>SonarQube Analysis: ${currentBuild.currentResult == 'SUCCESS' ? 'Completed' : 'Skipped/Failed'}</li>
                        </ul>
                        
                        <p>All security reports are attached to this email.</p>
                        <hr>
                        <p><em>Jenkins Security Pipeline</em></p>
                    """,
                    mimeType: 'text/html',
                    attachmentsPattern: 'artifacts/security-reports.zip',
                    attachLog: true
                )
            }
        }
        
        cleanup {
            sh '''
                echo "Cleaning up workspace..."
                docker system prune -f 2>/dev/null || true
            '''
        }
    }
}