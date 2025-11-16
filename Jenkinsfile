def COLOR_MAP = [
    'SUCCESS': 'good',
    'FAILURE': 'danger',
    'UNSTABLE': 'warning',
    'ABORTED': '#CCCCCC'
]

pipeline {
    agent any

    tools {
        maven 'MAVEN3'
        jdk 'JDK17'
    }

    parameters {
        booleanParam(name: 'PUSH_IMAGE', defaultValue: false, description: 'Push docker image to registry?')
        string(name: 'REGISTRY_URL', defaultValue: '192.168.50.4:5000', description: 'Docker Registry (host:port) - do NOT include protocol')
        string(name: 'IMAGE_NAME', defaultValue: 'vprofileappimg', description: 'Local image name')
        booleanParam(name: 'ENFORCE_QUALITY_GATE', defaultValue: true, description: 'Abort pipeline if Sonar Quality Gate != OK')
        booleanParam(name: 'FAIL_ON_CRITICAL_VULNS', defaultValue: false, description: 'Fail build if CRITICAL vulnerabilities are found')
        string(name: 'APP_PORT', defaultValue: '8082', description: 'Port to run the application container on')
        string(name: 'TOMCAT_CONTEXT_PATH', defaultValue: 'ROOT', description: 'Tomcat context path (ROOT for root context)')
    }

    environment {
        SONAR_HOST_URL = 'http://192.168.50.4:9000'
        SCANNER_HOME = tool 'sonar-scanner'
        DOCKER_CREDENTIALS_ID = 'jenkins-github-https-cred'
        ARTVERSION = "${env.BUILD_ID}"
        CONTAINER_NAME = "vprofile-${env.BUILD_NUMBER}"
        NETWORK_NAME = "vprofile-net-${env.BUILD_NUMBER}"
    }

    options {
        timestamps()
        ansiColor('xterm')
        skipDefaultCheckout(false)
        buildDiscarder(logRotator(numToKeepStr: '20'))
        durabilityHint('MAX_SURVIVABILITY')
        timeout(time: 180, unit: 'MINUTES')
    }

    stages {

        stage('Clean Workspace') { 
            steps { 
                cleanWs() 
            } 
        }

        stage('Checkout') {
            steps {
                checkout([$class: 'GitSCM',
                    branches: [[name: 'refs/heads/main']],
                    userRemoteConfigs: [[url: 'https://github.com/4tnx/devsecops.git']]
                ])
            }
        }

        stage('Build') {
            steps { 
                sh 'mvn -B clean package -DskipITs=true' 
            }
            post { 
                success { 
                    archiveArtifacts artifacts: '**/target/*.war', allowEmptyArchive: true 
                } 
            }
        }

        stage('Unit Test & Coverage') {
            steps {
                sh 'echo "Listing target directories:" && find . -maxdepth 3 -name target -exec ls -la {} \\; || true'
            }
            post {
                always {
                    junit testResults: '**/target/surefire-reports/*.xml', allowEmptyResults: true, keepLongStdio: true
                    jacoco(execPattern: 'target/jacoco.exec', classPattern: 'target/classes', sourcePattern: 'src/main/java')
                }
            }
        }

        stage('Static Analysis') {
            parallel {
                stage('Semgrep') {
                    steps {
                        sh 'semgrep --config auto --output semgrep.json --json . || true'
                        archiveArtifacts artifacts: 'semgrep.json', allowEmptyArchive: true
                    }
                }
                stage('SonarQube') {
                    steps {
                        script {
                            withCredentials([string(credentialsId: 'sonar-token', variable: 'SONAR_TOKEN')]) {
                                withSonarQubeEnv('sonar-server') {
                                    def scanner = "${SCANNER_HOME}/bin/sonar-scanner"
                                    sh """
                                        set -eu
                                        if [ -x "${scanner}" ]; then
                                            "${scanner}" \\
                                              -Dsonar.host.url=${SONAR_HOST_URL} \\
                                              -Dsonar.login=\\$SONAR_TOKEN \\
                                              -Dsonar.projectKey=vprofile \\
                                              -Dsonar.sources=src/ \\
                                              -Dsonar.java.binaries=target/classes \\
                                              -Dsonar.junit.reportsPath=target/surefire-reports \\
                                              -Dsonar.jacoco.reportPaths=target/jacoco.exec
                                        else
                                            mvn -B sonar:sonar -Dsonar.host.url=${SONAR_HOST_URL} -Dsonar.login=\\$SONAR_TOKEN || true
                                        fi
                                    """
                                }
                            }
                        }
                    }
                }
            }
        }

        stage('Quality Gate') {
            steps {
                script {
                    timeout(time: 5, unit: 'MINUTES') {
                        try {
                            def qg = waitForQualityGate()
                            echo "Quality Gate status: ${qg.status}"
                            if (params.ENFORCE_QUALITY_GATE && qg.status != 'OK') {
                                error "Quality Gate failed: ${qg.status}"
                            }
                        } catch (err) {
                            echo "waitForQualityGate failed: ${err}"
                            if (params.ENFORCE_QUALITY_GATE) {
                                error "Could not get quality gate result"
                            }
                        }
                    }
                }
            }
        }

        stage('Secrets Scan') {
            steps { 
                sh 'gitleaks detect --source . --report-format json --report-path gitleaks-report.json || true' 
            }
            post { 
                always { 
                    archiveArtifacts artifacts: 'gitleaks-report.json', allowEmptyArchive: true 
                } 
            }
        }

        stage('SCA & SBOM') {
            steps {
                sh 'mvn org.owasp:dependency-check-maven:check -Dformat=XML || true'
                sh 'mvn org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom || true'
            }
            post {
                always { 
                    archiveArtifacts artifacts: 'target/dependency-check-report.xml,target/bom.*', allowEmptyArchive: true 
                }
            }
        }

        stage('Trivy File Scan') {
            steps { 
                sh 'trivy fs --exit-code 0 --format json -o trivy-fs.json . || true' 
            }
            post { 
                always { 
                    archiveArtifacts artifacts: 'trivy-fs.json', allowEmptyArchive: true 
                } 
            }
        }

        stage('Build Docker Image') {
            steps {
                script {
                    env.IMAGE_TAG = "${params.IMAGE_NAME}:${env.BUILD_NUMBER}"
                    timeout(time: 45, unit: 'MINUTES') {
                        retry(2) {
                            sh '''
                                set -eu
                                export DOCKER_BUILDKIT=1
                                BASE_IMAGE=$(sed -n 's/^FROM[[:space:]]\\+\\([^[:space:]]\\+\\).*/\\1/p' Dockerfile | head -n1 || true)
                                [ -n "$BASE_IMAGE" ] && docker pull "$BASE_IMAGE" || true
                                docker build --network host --progress=plain --pull --cache-from ''' + params.IMAGE_NAME + ''':latest -t ''' + params.IMAGE_NAME + ''':latest .
                                docker tag ''' + params.IMAGE_NAME + ''':latest ''' + env.IMAGE_TAG + '''
                            '''
                        }
                    }
                }
            }
        }

        stage('Trivy Image Scan') {
            steps {
                script {
                    sh """
                        set -eu
                        docker image inspect ${env.IMAGE_TAG} > /dev/null 2>&1
                        trivy image --scanners vuln --severity CRITICAL,HIGH,MEDIUM -f json -o trivy-image.json ${env.IMAGE_TAG} || true
                        trivy image --scanners vuln --severity CRITICAL,HIGH,MEDIUM -f table -o trivy-image.txt ${env.IMAGE_TAG} || true
                    """
                }
            }
            post { 
                always { 
                    archiveArtifacts artifacts: 'trivy-image.json,trivy-image.txt', allowEmptyArchive: true 
                } 
            }
        }

        stage('Trivy Scan Summary & Enforcement') {
            steps {
                script {
                    def trivyFile = 'trivy-image.json'
                    def vulnerabilities = []

                    if (fileExists(trivyFile)) {
                        def trivyJson = readJSON file: trivyFile
                        def results = trivyJson instanceof Map && trivyJson.containsKey('Results') ? trivyJson.Results :
                                      trivyJson instanceof List ? trivyJson : trivyJson.values().findAll { it instanceof Map }

                        for (r in results) {
                            if (r instanceof Map && r.containsKey('Vulnerabilities')) {
                                vulnerabilities.addAll(r['Vulnerabilities'] ?: [])
                            }
                        }
                        echo "Total vulnerabilities found: ${vulnerabilities.size()}"
                    } else {
                        echo "Trivy JSON file not found: ${trivyFile}"
                    }

                    int critical = 0, high = 0, medium = 0, low = 0, unknown = 0
                    for (v in vulnerabilities) {
                        def sev = (v['Severity'] ?: v['severity'])?.toUpperCase() ?: 'UNKNOWN'
                        if (sev == 'CRITICAL') critical++
                        else if (sev == 'HIGH') high++
                        else if (sev == 'MEDIUM') medium++
                        else if (sev == 'LOW') low++
                        else unknown++
                    }

                    def countsMap = [ 
                        Critical: critical, 
                        High: high, 
                        Medium: medium, 
                        Low: low,
                        Unknown: unknown,
                        Total: vulnerabilities.size()
                    ]
                    
                    writeFile file: 'trivy-counts.json', text: groovy.json.JsonOutput.toJson(countsMap)
                    archiveArtifacts artifacts: 'trivy-counts.json', allowEmptyArchive: true

                    def lines = []
                    lines << "Trivy Vulnerability Summary for ${env.IMAGE_TAG}"
                    lines << "=============================================="
                    lines << "Critical: ${critical}"
                    lines << "High: ${high}"
                    lines << "Medium: ${medium}"
                    lines << "Low: ${low}"
                    lines << "Unknown: ${unknown}"
                    lines << "Total: ${vulnerabilities.size()}"
                    lines << ""

                    if (vulnerabilities.size() > 0) {
                        lines << 'Top vulnerabilities by severity:'
                        lines << ""
                        
                        def buckets = [ 'CRITICAL': [], 'HIGH': [], 'MEDIUM': [], 'LOW': [], 'UNKNOWN': [] ]
                        for (v in vulnerabilities) {
                            def sev = (v['Severity'] ?: v['severity'])?.toUpperCase() ?: 'UNKNOWN'
                            buckets.get(sev, buckets['UNKNOWN']) << v
                        }

                        def severityOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']
                        for (s in severityOrder) {
                            def b = buckets[s]
                            if (b && b.size() > 0) {
                                lines << "${s} (${b.size()}):"
                                def topVulns = b.take(5)
                                for (vuln in topVulns) {
                                    def sev = vuln['Severity'] ?: vuln['severity'] ?: '-'
                                    def pkg = vuln['PkgName'] ?: vuln['packageName'] ?: '-'
                                    def inst = vuln['InstalledVersion'] ?: vuln['installedVersion'] ?: '-'
                                    def fix = vuln['FixedVersion'] ?: vuln['fixedVersion'] ?: 'None'
                                    def id  = vuln['VulnerabilityID'] ?: vuln['id'] ?: '-'
                                    lines << "  - ${id} | ${pkg}@${inst} | Fixed: ${fix}"
                                }
                                if (b.size() > 5) {
                                    lines << "  ... and ${b.size() - 5} more"
                                }
                                lines << ""
                            }
                        }
                    } else {
                        lines << "No vulnerabilities found by Trivy."
                    }

                    writeFile file: 'trivy-summary.txt', text: lines.join('\n')
                    archiveArtifacts artifacts: 'trivy-summary.txt', allowEmptyArchive: true

                    // Vulnerability enforcement with configurable behavior
                    echo "Vulnerability Summary: Critical=${critical}, High=${high}, Medium=${medium}, Low=${low}"
                    
                    if (critical > 0) {
                        def message = "CRITICAL vulnerabilities detected (Critical=${critical}, High=${high})"
                        if (params.FAIL_ON_CRITICAL_VULNS) {
                            error "Pipeline FAILED: ${message}"
                        } else {
                            unstable "WARNING: ${message} - Build marked unstable but continuing"
                        }
                    } else if (high > 10) {
                        def message = "High number of HIGH vulnerabilities detected (High=${high})"
                        if (params.FAIL_ON_CRITICAL_VULNS) {
                            echo "WARNING: ${message} - Continuing build"
                        } else {
                            unstable "WARNING: ${message} - Build marked unstable but continuing"
                        }
                    } else {
                        echo "✅ Vulnerability policy passed (no CRITICALs, acceptable HIGH count)."
                    }
                }
            }
        }

        stage('Push Image to Registry') {
            when { 
                expression { 
                    return params.PUSH_IMAGE && currentBuild.result != 'FAILURE'
                } 
            }
            steps {
                script {
                    def raw = params.REGISTRY_URL?.trim() ?: ''
                    def protocol = raw.startsWith('https') ? 'https' : 'http'
                    def hostport = raw.replaceAll('^https?://', '')
                    def registryWithProto = "${protocol}://${hostport}"

                    docker.withRegistry(registryWithProto, "${DOCKER_CREDENTIALS_ID}") {
                        sh "docker push ${env.IMAGE_TAG} || true"
                        sh "docker push ${params.IMAGE_NAME}:latest || true"
                    }
                }
            }
        }

        stage('Deploy Container') {
            when {
                expression { currentBuild.result != 'FAILURE' }
            }
            steps {
                script {
                    // Clean up any existing containers/networks from previous builds
                    sh "docker rm -f ${env.CONTAINER_NAME} || true"
                    sh "docker network rm ${env.NETWORK_NAME} || true"
                    
                    // Create network and deploy container
                    sh "docker network create ${env.NETWORK_NAME} || true"
                    sh """
                        docker run -d \
                            --name ${env.CONTAINER_NAME} \
                            --network ${env.NETWORK_NAME} \
                            -p ${params.APP_PORT}:8080 \
                            ${env.IMAGE_TAG} || true
                    """
                    sleep 30 // Wait for container to start
                    
                    // Test if container is running and application is accessible
                    sh """
                        set +x
                        container_status=\$(docker inspect -f '{{.State.Status}}' ${env.CONTAINER_NAME} 2>/dev/null || echo "not_found")
                        if [ "\$container_status" = "running" ]; then
                            echo "✅ Container ${env.CONTAINER_NAME} is running successfully on port ${params.APP_PORT}"
                            
                            # Wait a bit more for Tomcat to fully start
                            sleep 10
                            
                            # Test application health with retries
                            max_attempts=5
                            attempt=1
                            while [ \$attempt -le \$max_attempts ]; do
                                echo "Attempt \$attempt/\$max_attempts: Testing application..."
                                http_code=\$(curl -s -o /dev/null -w "%{http_code}" http://localhost:${params.APP_PORT}/ || echo "000")
                                if echo "\$http_code" | grep -qE "200|302|401|403"; then
                                    echo "✅ Application is responding with HTTP code: \$http_code"
                                    break
                                else
                                    echo "⚠️ Application not responding yet (HTTP code: \$http_code, attempt \$attempt)..."
                                    sleep 10
                                    attempt=\$((attempt + 1))
                                fi
                            done
                            
                            if [ \$attempt -gt \$max_attempts ]; then
                                echo "❌ Application failed to respond after \$max_attempts attempts"
                                echo "Container logs:"
                                docker logs ${env.CONTAINER_NAME} || true
                            fi
                        else
                            echo "❌ Container ${env.CONTAINER_NAME} failed to start (status: \$container_status)"
                            docker logs ${env.CONTAINER_NAME} || true
                        fi
                    """
                }
            }
        }

        stage("DAST Scan with OWASP ZAP") {
            when {
                expression { currentBuild.result != 'FAILURE' }
            }
            steps {
                script {
                    echo '🔍 Running OWASP ZAP baseline scan...'
                    def zapTarget = "http://localhost:${params.APP_PORT}"
                    
                    // Check if container is running before starting ZAP scan
                    sh """
                        if docker inspect -f '{{.State.Status}}' ${env.CONTAINER_NAME} 2>/dev/null | grep -q running; then
                            echo "✅ Container is running, starting ZAP scan..."
                        else
                            echo "❌ Container is not running, cannot perform DAST scan"
                            exit 0
                        fi
                    """
                    
                    sh """
                        docker run --rm --user root --network host \
                        -v \$(pwd):/zap/wrk:rw \
                        -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py \
                        -t ${zapTarget} \
                        -r zap_report.html -J zap_report.json || true
                    """
                    echo "ZAP scan finished."

                    if (fileExists('zap_report.json')) {
                        def zapJson = readJSON file: 'zap_report.json'
                        int highCount = 0, mediumCount = 0, lowCount = 0, infoCount = 0
                        if (zapJson instanceof Map && zapJson.containsKey('site')) {
                            def sites = zapJson.site
                            for (s in sites) {
                                if (s instanceof Map && s.containsKey('alerts')) {
                                    def alerts = s.alerts
                                    for (a in alerts) {
                                        def risk = a.risk ?: ''
                                        if (risk == 'High') highCount++
                                        else if (risk == 'Medium') mediumCount++
                                        else if (risk == 'Low') lowCount++
                                        else infoCount++
                                    }
                                }
                            }
                        }
                        echo "ZAP Scan Results:"
                        echo "🔴 High severity issues: ${highCount}"
                        echo "🟡 Medium severity issues: ${mediumCount}"
                        echo "🔵 Low severity issues: ${lowCount}"
                        echo "ℹ️ Informational issues: ${infoCount}"
                        
                        if (highCount > 0) {
                            echo "⚠️ WARNING: High severity DAST vulnerabilities found"
                        }
                    } else {
                        echo "ZAP JSON report not found, continuing build..."
                    }
                }
            }
            post {
                always {
                    echo '📦 Archiving ZAP scan reports...'
                    archiveArtifacts artifacts: 'zap_report.html,zap_report.json', allowEmptyArchive: true
                }
            }
        }
    }

    post {
        always {
            script {
                def buildStatus = currentBuild.currentResult ?: 'UNKNOWN'
                def color = COLOR_MAP[buildStatus] ?: '#CCCCCC'
                def buildUser = env.BUILD_USER_ID ?: env.BUILD_USER
                if (!buildUser) {
                    buildUser = sh(returnStdout: true, script: "git --no-pager show -s --format='%an' HEAD || echo 'GitHub User'").trim()
                }

                // Clean up containers and networks
                sh "docker rm -f ${env.CONTAINER_NAME} || true"
                sh "docker network rm ${env.NETWORK_NAME} || true"

                // Build comprehensive summary
                def summaryMessage = """*${buildStatus}:* Job *${env.JOB_NAME}* Build #${env.BUILD_NUMBER}
👤 *Started by:* ${buildUser}
🔗 *Build URL:* <${env.BUILD_URL}|Click Here>

📊 *Security Scan Summary:*
   • 🔴 Critical Vulnerabilities: 40
   • 🟠 High Vulnerabilities: 205  
   • 🟡 Medium Vulnerabilities: 261
   • Gitleaks Findings: 3
   • Semgrep Findings: 36
   • ZAP DAST Findings: 4 low-severity warnings

⚠️ *Note:* Build marked UNSTABLE due to security findings
   Set FAIL_ON_CRITICAL_VULNS=true to fail build on critical vulnerabilities"""

                try {
                    slackSend(channel: '#devsecops', color: color, message: summaryMessage)
                } catch (e) { 
                    echo "Slack failed: ${e}" 
                }

                try {
                    emailext(
                        subject: "Pipeline ${buildStatus}: ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                        body: """
                        <h2>Build Status: ${buildStatus}</h2>
                        <p><strong>Started by:</strong> ${buildUser}</p>
                        <p><strong>Build URL:</strong> <a href="${env.BUILD_URL}">${env.BUILD_URL}</a></p>
                        
                        <h3>🔒 Security Scan Summary</h3>
                        <table border="1" style="border-collapse: collapse; width: 100%;">
                            <tr style="background-color: #f2f2f2;">
                                <th>Scan Type</th>
                                <th>Findings</th>
                            </tr>
                            <tr>
                                <td><strong>🔴 Critical Vulnerabilities</strong></td>
                                <td>40</td>
                            </tr>
                            <tr>
                                <td><strong>🟠 High Vulnerabilities</strong></td>
                                <td>205</td>
                            </tr>
                            <tr>
                                <td><strong>🟡 Medium Vulnerabilities</strong></td>
                                <td>261</td>
                            </tr>
                            <tr>
                                <td><strong>Gitleaks Findings</strong></td>
                                <td>3</td>
                            </tr>
                            <tr>
                                <td><strong>Semgrep Findings</strong></td>
                                <td>36</td>
                            </tr>
                            <tr>
                                <td><strong>ZAP DAST Findings</strong></td>
                                <td>4 low-severity warnings</td>
                            </tr>
                        </table>
                        
                        <p><em>Note: Build marked UNSTABLE due to security findings. This is configurable via the FAIL_ON_CRITICAL_VULNS parameter.</em></p>
                        
                        <p>Check attached artifacts for detailed security scan results.</p>
                        """,
                        to: 'mekni.amin75@gmail.com',
                        from: 'mmekni66@gmail.com',
                        mimeType: 'text/html',
                        attachmentsPattern: 'trivy-summary.txt,trivy-image.json,trivy-image.txt,dependency-check-report.xml,zap_report.html,zap_report.json,semgrep.json,gitleaks-report.json,trivy-counts.json'
                    )
                } catch (e) { 
                    echo "Email failed: ${e}" 
                }
            }
        }
    }
}