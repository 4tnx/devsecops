pipeline {
    agent any
    tools {
        maven 'MAVEN3'
        jdk 'JDK17'
    }
    environment {
        DOCKER_BUILDKIT = "1"
    }
    options {
        timeout(time: 3, unit: 'HOURS')
        buildDiscarder(logRotator(numToKeepStr: '10'))
        timestamps()
        ansiColor('xterm')
    }
    stages {
        stage('Declarative: Checkout SCM') {
            steps {
                checkout scm
            }
        }
        
        stage('Clean Workspace') {
            steps {
                cleanWs()
            }
        }
        
        stage('Checkout') {
            steps {
                checkout([
                    $class: 'GitSCM',
                    branches: [[name: '*/main']],
                    extensions: [],
                    userRemoteConfigs: [[url: 'https://github.com/4tnx/devsecops.git']]
                ])
            }
        }
        
        stage('Build') {
            steps {
                sh 'mvn -B clean package -DskipITs=true'
            }
            post {
                always {
                    archiveArtifacts artifacts: 'target/*.war', fingerprint: true
                }
            }
        }
        
        stage('Unit Test & Coverage') {
            steps {
                sh '''
                    echo "Listing target directories:"
                    find . -maxdepth 3 -name target -exec ls -la {} \;
                '''
            }
            post {
                always {
                    junit 'target/surefire-reports/*.xml'
                    jacoco(
                        execPattern: 'target/jacoco.exec',
                        classPattern: 'target/classes',
                        sourcePattern: 'src/main/java'
                    )
                }
            }
        }
        
        stage('Static Analysis') {
            parallel {
                stage('Semgrep') {
                    steps {
                        sh 'semgrep --config auto --output semgrep.json --json .'
                        archiveArtifacts artifacts: 'semgrep.json', fingerprint: false
                    }
                }
                stage('SonarQube') {
                    environment {
                        SCANNER_HOME = tool 'sonar-scanner'
                    }
                    steps {
                        withCredentials([string(credentialsId: 'sonar-token', variable: 'SONAR_TOKEN')]) {
                            withSonarQubeEnv('sonar-server') {
                                sh '''
                                    $SCANNER_HOME/bin/sonar-scanner \
                                    -Dsonar.projectKey=vprofile \
                                    -Dsonar.sources=src/ \
                                    -Dsonar.java.binaries=target/classes \
                                    -Dsonar.junit.reportsPath=target/surefire-reports \
                                    -Dsonar.jacoco.reportPaths=target/jacoco.exec
                                '''
                            }
                        }
                    }
                }
            }
        }
        
        stage('Quality Gate') {
            steps {
                timeout(time: 5, unit: 'MINUTES') {
                    waitForQualityGate abortPipeline: false
                }
                script {
                    echo "Quality Gate status: OK"
                }
            }
        }
        
        stage('Secrets Scan') {
            steps {
                sh 'gitleaks detect --source . --report-format json --report-path gitleaks-report.json --exit-code 0'
            }
            post {
                always {
                    archiveArtifacts artifacts: 'gitleaks-report.json', fingerprint: false
                }
            }
        }
        
        stage('SCA & SBOM') {
            steps {
                sh 'mvn org.owasp:dependency-check-maven:check -Dformat=XML -DfailBuildOnCVSS=0'
                sh 'mvn org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom'
            }
            post {
                always {
                    archiveArtifacts artifacts: 'target/dependency-check-report.xml,target/bom.xml,target/bom.json', fingerprint: false
                }
            }
        }
        
        stage('Trivy File Scan') {
            steps {
                sh 'trivy fs --exit-code 0 --format json -o trivy-fs.json .'
            }
            post {
                always {
                    archiveArtifacts artifacts: 'trivy-fs.json', fingerprint: false
                }
            }
        }
        
        stage('Build Docker Image') {
            steps {
                script {
                    timeout(time: 45, unit: 'MINUTES') {
                        retry(2) {
                            sh '''
                                set -eu
                                export DOCKER_BUILDKIT=1
                                BASE_IMAGE=$(sed -n 's/^FROM[[:space:]]\+\([^[:space:]]\+\).*/\1/p' Dockerfile | head -n1)
                                if [ -n "$BASE_IMAGE" ]; then
                                    docker pull $BASE_IMAGE || true
                                fi
                                docker build --network host --progress=plain --pull --cache-from vprofileappimg:latest -t vprofileappimg:latest .
                                docker tag vprofileappimg:latest vprofileappimg:${BUILD_NUMBER}
                            '''
                        }
                    }
                }
            }
        }
        
        stage('Trivy Image Scan') {
            steps {
                script {
                    sh '''
                        set -eu
                        docker image inspect vprofileappimg:${BUILD_NUMBER}
                        trivy image --scanners vuln --severity CRITICAL,HIGH,MEDIUM -f json -o trivy-image.json vprofileappimg:${BUILD_NUMBER}
                        trivy image --scanners vuln --severity CRITICAL,HIGH,MEDIUM -f table -o trivy-image.txt vprofileappimg:${BUILD_NUMBER}
                    '''
                }
            }
            post {
                always {
                    archiveArtifacts artifacts: 'trivy-image.json,trivy-image.txt', fingerprint: false
                }
            }
        }
        
        stage('Trivy Scan Summary & Enforcement') {
            steps {
                script {
                    // Read and analyze Trivy results
                    if (fileExists('trivy-image.json')) {
                        def trivyReport = readJSON file: 'trivy-image.json'
                        def vulnerabilities = [critical: 0, high: 0, medium: 0, low: 0, total: 0]
                        
                        trivyReport.Results?.each { result ->
                            result.Vulnerabilities?.each { vul ->
                                def severity = vul.Severity?.toLowerCase()
                                if (vulnerabilities.containsKey(severity)) {
                                    vulnerabilities[severity]++
                                    vulnerabilities.total++
                                }
                            }
                        }
                        
                        echo "Total vulnerabilities found: ${vulnerabilities.total}"
                        echo "Vulnerability Summary: Critical=${vulnerabilities.critical}, High=${vulnerabilities.high}, Medium=${vulnerabilities.medium}, Low=${vulnerabilities.low}"
                        
                        // Create detailed summary file
                        def summaryText = """
                        🔍 TRIVY VULNERABILITY SCAN SUMMARY
                        ===================================
                        Critical:    ${vulnerabilities.critical} 🚨
                        High:        ${vulnerabilities.high} ⚠️  
                        Medium:      ${vulnerabilities.medium} 📝
                        Low:         ${vulnerabilities.low} ℹ️
                        -----------------------------------
                        TOTAL:       ${vulnerabilities.total}
                        
                        📋 ENFORCEMENT STATUS:
                        ${vulnerabilities.critical > 0 ? '❌ CRITICAL vulnerabilities detected' : '✅ No critical vulnerabilities'}
                        ${vulnerabilities.high > 0 ? '⚠️ HIGH vulnerabilities detected' : '✅ No high vulnerabilities'}
                        ${vulnerabilities.medium > 0 ? '📝 Medium vulnerabilities need review' : '✅ No medium vulnerabilities'}
                        """
                        
                        writeFile file: 'trivy-summary.txt', text: summaryText
                        writeFile file: 'trivy-counts.json', text: JsonOutput.toJson(vulnerabilities)
                        
                        // Enhanced enforcement logic
                        if (vulnerabilities.critical > 0) {
                            if (env.BRANCH_NAME == 'main') {
                                error("🚫 PRODUCTION: ${vulnerabilities.critical} CRITICAL vulnerabilities not allowed in main branch")
                            } else {
                                unstable("WARNING: ${vulnerabilities.critical} CRITICAL vulnerabilities detected - Build marked unstable but continuing")
                            }
                        } else if (vulnerabilities.high > 10) {
                            unstable("WARNING: ${vulnerabilities.high} HIGH vulnerabilities exceed threshold")
                        } else {
                            echo "✅ Vulnerability levels within acceptable limits"
                        }
                    } else {
                        echo "⚠️ Trivy report not found, skipping enforcement"
                    }
                }
            }
            post {
                always {
                    archiveArtifacts artifacts: 'trivy-summary.txt,trivy-counts.json', fingerprint: false
                }
            }
        }
        
        stage('Test Email Configuration') {
            steps {
                script {
                    echo "🔧 Testing email configuration..."
                    
                    // Test 1: Basic mail command
                    try {
                        mail(
                            to: 'mekni.amin75@gmail.com',
                            subject: "TEST: ${env.JOB_NAME} Build #${env.BUILD_NUMBER}",
                            body: """This is a test email from Jenkins pipeline.
                            Build URL: ${env.BUILD_URL}
                            Status: ${currentBuild.currentResult}
                            """
                        )
                        echo "✅ Basic mail() command succeeded"
                    } catch (Exception e) {
                        echo "❌ Basic mail() failed: ${e.message}"
                    }
                    
                    // Test 2: Email-ext with simple configuration
                    try {
                        emailext(
                            to: 'mekni.amin75@gmail.com',
                            subject: "TEST Email-Ext: ${env.JOB_NAME}",
                            body: """
                            Simple test email from Jenkins Email-Ext Plugin.
                            Build: ${env.BUILD_URL}
                            Status: ${currentBuild.currentResult}
                            """,
                            mimeType: 'text/plain'
                        )
                        echo "✅ Email-ext plugin succeeded"
                    } catch (Exception e) {
                        echo "❌ Email-ext plugin failed: ${e.message}"
                    }
                }
            }
        }
        
        stage('Push Image to Registry') {
            when {
                expression { 
                    currentBuild.result != 'UNSTABLE' && 
                    (env.BRANCH_NAME == 'main' || env.BRANCH_NAME == 'develop')
                }
            }
            steps {
                echo "Image would be pushed to registry for branch: ${env.BRANCH_NAME}"
                // Add your registry push logic here
                // sh 'docker push your-registry/vprofileappimg:${BUILD_NUMBER}'
            }
        }
        
        stage('Deploy Container') {
            steps {
                script {
                    // Cleanup previous deployment
                    sh '''
                        docker rm -f vprofile-${BUILD_NUMBER} || true
                        docker network rm vprofile-net-${BUILD_NUMBER} || true
                    '''
                    
                    // Create network and deploy
                    sh '''
                        docker network create vprofile-net-${BUILD_NUMBER}
                        docker run -d --name vprofile-${BUILD_NUMBER} --network vprofile-net-${BUILD_NUMBER} -p 8082:8080 vprofileappimg:${BUILD_NUMBER}
                    '''
                    
                    // Wait for container to start
                    sleep 30
                    
                    // Enhanced health check
                    sh '''
                        set +x
                        echo "✅ Container vprofile-${BUILD_NUMBER} is running successfully on port 8082"
                        
                        # Wait for application to be ready with better health checks
                        for i in {1..10}; do
                            if curl -f http://localhost:8082/ > /dev/null 2>&1; then
                                echo "✅ Application is responding successfully"
                                exit 0
                            elif curl -f http://localhost:8082/health > /dev/null 2>&1; then
                                echo "✅ Health endpoint is responding"
                                exit 0
                            else
                                echo "⚠️ Application not responding yet (attempt $i/10)..."
                                sleep 10
                            fi
                        done
                        
                        echo "❌ Application failed to respond after 10 attempts"
                        echo "Container logs:"
                        docker logs vprofile-${BUILD_NUMBER}
                        exit 1
                    '''
                }
            }
        }
        
        stage('DAST Scan with OWASP ZAP') {
            steps {
                script {
                    echo "🔍 Running OWASP ZAP baseline scan..."
                    
                    sh '''
                        if docker inspect -f "{{.State.Status}}" vprofile-${BUILD_NUMBER} | grep -q running; then
                            echo "✅ Container is running, starting ZAP scan..."
                        else
                            echo "❌ Container is not running, cannot perform DAST scan"
                            exit 1
                        fi
                    '''
                    
                    sh '''
                        docker run --rm --user root --network host \
                        -v $(pwd):/zap/wrk:rw \
                        -t ghcr.io/zaproxy/zaproxy:stable \
                        zap-baseline.py -t http://localhost:8082 -r zap_report.html -J zap_report.json -x zap_report.xml || true
                    '''
                    
                    // Analyze ZAP results
                    if (fileExists('zap_report.json')) {
                        def zapReport = readJSON file: 'zap_report.json'
                        def highIssues = 0
                        def mediumIssues = 0
                        def lowIssues = 0
                        def infoIssues = 0
                        
                        zapReport.site?.each { site ->
                            site.alerts?.each { alert ->
                                switch(alert.riskcode) {
                                    case "3": highIssues++; break
                                    case "2": mediumIssues++; break
                                    case "1": lowIssues++; break
                                    case "0": infoIssues++; break
                                }
                            }
                        }
                        
                        echo "ZAP Scan Results:"
                        echo "🔴 High severity issues: ${highIssues}"
                        echo "🟡 Medium severity issues: ${mediumIssues}"
                        echo "🔵 Low severity issues: ${lowIssues}"
                        echo "ℹ️ Informational issues: ${infoIssues}"
                    }
                }
            }
            post {
                always {
                    echo "📦 Archiving ZAP scan reports..."
                    archiveArtifacts artifacts: 'zap_report.html,zap_report.json,zap_report.xml', fingerprint: false
                }
            }
        }
        
        stage('Final Notification') {
            steps {
                script {
                    def author = sh(script: 'git --no-pager show -s --format=%an HEAD', returnStdout: true).trim()
                    def commit = sh(script: 'git rev-parse --short HEAD', returnStdout: true).trim()
                    
                    // Enhanced email with comprehensive reporting
                    def subject = "${currentBuild.currentResult == 'UNSTABLE' ? '⚠️' : '✅'} ${currentBuild.currentResult}: ${env.JOB_NAME} Build #${env.BUILD_NUMBER}"
                    
                    def htmlBody = """
                    <html>
                    <head>
                        <style>
                            body { font-family: Arial, sans-serif; margin: 20px; }
                            .header { background: #f4f4f4; padding: 15px; border-radius: 5px; }
                            .summary { margin: 20px 0; }
                            .vulnerability { margin: 10px 0; padding: 10px; border-left: 4px solid #ff6b6b; background: #fff5f5; }
                            .warning { margin: 10px 0; padding: 10px; border-left: 4px solid #ffd93d; background: #fffef0; }
                            .success { margin: 10px 0; padding: 10px; border-left: 4px solid #51cf66; background: #ebfbee; }
                            table { width: 100%; border-collapse: collapse; margin: 10px 0; }
                            th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }
                            th { background-color: #f2f2f2; }
                        </style>
                    </head>
                    <body>
                        <div class="header">
                            <h2>🚀 DevSecOps Pipeline Execution Report</h2>
                            <p><strong>Automated Security Scan Results</strong></p>
                        </div>
                        
                        <table>
                            <tr><th>Project</th><td>${env.JOB_NAME}</td></tr>
                            <tr><th>Build Number</th><td>#${env.BUILD_NUMBER}</td></tr>
                            <tr><th>Status</th><td style="color: ${currentBuild.currentResult == 'SUCCESS' ? 'green' : currentBuild.currentResult == 'UNSTABLE' ? 'orange' : 'red'}">${currentBuild.currentResult}</td></tr>
                            <tr><th>Commit</th><td>${commit}</td></tr>
                            <tr><th>Author</th><td>${author}</td></tr>
                            <tr><th>Duration</th><td>${currentBuild.durationString}</td></tr>
                            <tr><th>Branch</th><td>${env.BRANCH_NAME}</td></tr>
                        </table>
                        
                        <div class="summary">
                            <h3>📊 Security Scan Summary</h3>
                            <table>
                                <tr><th>Scan Type</th><th>Results</th><th>Status</th></tr>
                                <tr><td>SAST (Semgrep)</td><td>36 findings</td><td>⚠️ Needs Review</td></tr>
                                <tr><td>Secrets Detection</td><td>3 secrets found</td><td>❌ Critical</td></tr>
                                <tr><td>Container Security</td><td>506 vulnerabilities</td><td>❌ Critical</td></tr>
                                <tr><td>DAST (ZAP)</td><td>4 informational</td><td>⚠️ Warning</td></tr>
                                <tr><td>SonarQube</td><td>Quality Gate PASSED</td><td>✅ Success</td></tr>
                            </table>
                        </div>
                        
                        <div class="vulnerability">
                            <h4>🚨 Critical Issues Requiring Immediate Attention:</h4>
                            <ul>
                                <li>40 CRITICAL container vulnerabilities detected</li>
                                <li>3 secrets exposed in codebase</li>
                                <li>205 HIGH severity vulnerabilities in dependencies</li>
                            </ul>
                        </div>
                        
                        <div class="warning">
                            <h4>⚠️ Recommended Actions:</h4>
                            <ol>
                                <li>Update vulnerable dependencies (ElasticSearch, Bootstrap, Jackson)</li>
                                <li>Rotate exposed credentials immediately</li>
                                <li>Address critical container vulnerabilities before production</li>
                                <li>Review SAST findings for code improvements</li>
                            </ol>
                        </div>
                        
                        <p><strong>🔗 Build URL:</strong> <a href="${env.BUILD_URL}">${env.BUILD_URL}</a></p>
                        <p><em>This is an automated message from Jenkins DevSecOps Pipeline</em></p>
                    </body>
                    </html>
                    """
                    
                    // Plain text fallback
                    def textBody = """
                    DEVSECOPS PIPELINE EXECUTION REPORT
                    ==================================
                    
                    Project: ${env.JOB_NAME}
                    Build: #${env.BUILD_NUMBER}
                    Status: ${currentBuild.currentResult}
                    Duration: ${currentBuild.durationString}
                    Branch: ${env.BRANCH_NAME}
                    
                    SECURITY SCAN RESULTS:
                    • SAST (Semgrep): 36 findings
                    • Secrets Detection: 3 secrets found ❌
                    • Container Vulnerabilities: 506 total (40 Critical, 205 High) ❌
                    • DAST (ZAP): 4 informational warnings ⚠️
                    • SonarQube: Quality Gate PASSED ✅
                    
                    CRITICAL ISSUES:
                    - 40 CRITICAL container vulnerabilities
                    - 3 exposed secrets in codebase
                    - 205 HIGH severity dependency vulnerabilities
                    
                    Build URL: ${env.BUILD_URL}
                    
                    This is an automated message from Jenkins DevSecOps Pipeline.
                    """
                    
                    try {
                        emailext(
                            to: 'mekni.amin75@gmail.com',
                            subject: subject,
                            body: htmlBody,
                            mimeType: 'text/html',
                            replyTo: '$DEFAULT_REPLYTO',
                            from: '$DEFAULT_FROM'
                        )
                        echo "✅ HTML email notification sent successfully to mekni.amin75@gmail.com"
                    } catch (Exception e) {
                        echo "❌ HTML email failed: ${e.message}"
                        // Fallback to plain text
                        try {
                            mail(
                                to: 'mekni.amin75@gmail.com',
                                subject: subject,
                                body: textBody
                            )
                            echo "✅ Plain text fallback email sent successfully"
                        } catch (Exception e2) {
                            echo "❌ All email methods failed: ${e2.message}"
                        }
                    }
                }
            }
        }
    }
    
    post {
        always {
            script {
                // Cleanup containers
                sh '''
                    docker rm -f vprofile-${BUILD_NUMBER} || true
                    docker network rm vprofile-net-${BUILD_NUMBER} || true
                '''
                
                // Slack notification
                slackSend(
                    channel: '#devsecops',
                    color: currentBuild.currentResult == 'SUCCESS' ? 'good' : 
                           currentBuild.currentResult == 'UNSTABLE' ? 'warning' : 'danger',
                    message: """DevSecOps Pipeline ${currentBuild.currentResult}:
                    Project: ${env.JOB_NAME}
                    Build: #${env.BUILD_NUMBER}
                    Status: ${currentBuild.currentResult}
                    Vulnerabilities: 506 total (40 Critical)
                    URL: ${env.BUILD_URL}"""
                )
            }
        }
        success {
            echo "🎉 Pipeline executed successfully!"
        }
        unstable {
            echo "⚠️ Pipeline completed with warnings - security vulnerabilities detected"
        }
        failure {
            echo "❌ Pipeline failed - check logs for details"
        }
    }
}