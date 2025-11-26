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
        // Ensure a Sonar scanner is configured in Jenkins global tools with this name
        sonarScanner 'sonar-scanner'
    }

    parameters {
        booleanParam(name: 'PUSH_IMAGE', defaultValue: false, description: 'Push docker image to registry?')
        string(name: 'REGISTRY_URL', defaultValue: '192.168.50.4:5000', description: 'Docker Registry (host:port) - do NOT include protocol')
        string(name: 'IMAGE_NAME', defaultValue: 'vprofileappimg', description: 'Local image name')
        booleanParam(name: 'ENFORCE_QUALITY_GATE', defaultValue: true, description: 'Abort pipeline if Sonar Quality Gate != OK')
        booleanParam(name: 'FAIL_ON_CRITICAL_VULNS', defaultValue: false, description: 'Fail build if CRITICAL vulnerabilities are found')
        booleanParam(name: 'FAIL_ON_HIGH_VULNS', defaultValue: false, description: 'Fail build if HIGH vulnerabilities exceed threshold')
        string(name: 'MAX_ALLOWED_HIGH_VULNS', defaultValue: '10', description: 'Number of HIGH vulnerabilities above which action is taken')
        string(name: 'APP_PORT', defaultValue: '8082', description: 'Port to run the application container on')
        string(name: 'TOMCAT_CONTEXT_PATH', defaultValue: 'ROOT', description: 'Tomcat context path (ROOT for root context)')
    }

    environment {
        SONAR_HOST_URL = 'http://192.168.50.4:9000'
        SCANNER_HOME = tool 'sonar-scanner'
        DOCKER_CREDENTIALS_ID = 'jenkins-github-https-cred'
        ARTVERSION = "${env.BUILD_NUMBER}"
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
                stage('Semgrep (SAST)') {
                    steps {
                        sh 'semgrep --config auto --output semgrep.json --json . || true'
                        archiveArtifacts artifacts: 'semgrep.json', allowEmptyArchive: true
                    }
                }
                stage('SonarQube (SAST)') {
                    steps {
                        script {
                            withCredentials([string(credentialsId: 'sonar-token', variable: 'SONAR_TOKEN')]) {
                                withSonarQubeEnv('sonar-server') {
                                    def scanner = "${SCANNER_HOME}/bin/sonar-scanner"
                                    sh """
                                        set -eu
                                        if [ -x "${scanner}" ]; then
                                            "${scanner}" \
                                              -Dsonar.host.url=${SONAR_HOST_URL} \
                                              -Dsonar.login=\$SONAR_TOKEN \
                                              -Dsonar.projectKey=vprofile \
                                              -Dsonar.sources=src/ \
                                              -Dsonar.java.binaries=target/classes \
                                              -Dsonar.junit.reportsPath=target/surefire-reports \
                                              -Dsonar.jacoco.reportPaths=target/jacoco.exec || true
                                        else
                                            mvn -B sonar:sonar -Dsonar.host.url=${SONAR_HOST_URL} -Dsonar.login=\$SONAR_TOKEN || true
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
                                BASE_IMAGE=$(sed -n 's/^FROM[[:space:]]\+\([^[:space:]]\+\).*/\1/p' Dockerfile | head -n1 || true)
                                [ -n "$BASE_IMAGE" ] && docker pull "$BASE_IMAGE" || true
                                docker build --network host --progress=plain --pull --cache-from ${params.IMAGE_NAME}:latest -t ${params.IMAGE_NAME}:latest .
                                docker tag ${params.IMAGE_NAME}:latest ${env.IMAGE_TAG}
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
                        docker image inspect ${env.IMAGE_TAG} > /dev/null 2>&1 || true
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

                    // Build human readable summary
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

                    // Enforcement logic
                    echo "Vulnerability Summary: Critical=${critical}, High=${high}, Medium=${medium}, Low=${low}"

                    if (critical > 0) {
                        def message = "CRITICAL vulnerabilities detected (Critical=${critical}, High=${high})"
                        if (params.FAIL_ON_CRITICAL_VULNS) {
                            error "Pipeline FAILED: ${message}"
                        } else {
                            unstable "WARNING: ${message} - Build marked unstable but continuing"
                        }
                    } else if (high > params.MAX_ALLOWED_HIGH_VULNS.toInteger()) {
                        def message = "High number of HIGH vulnerabilities detected (High=${high})"
                        if (params.FAIL_ON_HIGH_VULNS.toBoolean()) {
                            error "Pipeline FAILED: ${message}"
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
                    sh "docker rm -f ${env.CONTAINER_NAME} || true"
                    sh "docker network rm ${env.NETWORK_NAME} || true"

                    sh "docker network create ${env.NETWORK_NAME} || true"
                    sh '''
                        docker run -d \
                            --name ${CONTAINER_NAME} \
                            --network ${NETWORK_NAME} \
                            -p ${APP_PORT}:8080 \
                            ${IMAGE_TAG} || true
                    '''.replaceAll('\$\{CONTAINER_NAME\}', env.CONTAINER_NAME).replaceAll('\$\{NETWORK_NAME\}', env.NETWORK_NAME).replaceAll('\$\{APP_PORT\}', params.APP_PORT).replaceAll('\$\{IMAGE_TAG\}', env.IMAGE_TAG)

                    // Wait & healthcheck performed in one script for readability
                    sh '''
                        set +e
                        sleep 10
                        max_attempts=5
                        attempt=1
                        while [ $attempt -le $max_attempts ]; do
                            http_code=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:${APP_PORT}/ || echo "000")
                            if echo "$http_code" | grep -qE "200|302|401|403"; then
                                echo "Application is responding with HTTP code: $http_code"
                                exit 0
                            else
                                echo "Attempt $attempt: HTTP $http_code"
                                attempt=$((attempt + 1))
                                sleep 10
                            fi
                        done
                        echo "Application failed to respond after $max_attempts attempts"
                        docker logs ${CONTAINER_NAME} || true
                        exit 0
                    '''.replaceAll('\$\{APP_PORT\}', params.APP_PORT).replaceAll('\$\{CONTAINER_NAME\}', env.CONTAINER_NAME)
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

                    sh '''
                        if docker inspect -f '{{.State.Status}}' ${CONTAINER_NAME} 2>/dev/null | grep -q running; then
                            echo "Container is running, starting ZAP scan..."
                        else
                            echo "Container is not running, skipping ZAP scan"
                            exit 0
                        fi
                    '''.replaceAll('\$\{CONTAINER_NAME\}', env.CONTAINER_NAME)

                    sh """
                        docker run --rm --user root --network host \
                        -v \$(pwd):/zap/wrk:rw \
                        -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py \
                        -t ${zapTarget} \
                        -r zap_report.html -J zap_report.json || true
                    """

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
                        echo "ZAP Scan Results: High=${highCount}, Medium=${mediumCount}, Low=${lowCount}, Info=${infoCount}"
                        writeFile file: 'zap-counts.json', text: groovy.json.JsonOutput.toJson([high: highCount, medium: mediumCount, low: lowCount, info: infoCount])
                        archiveArtifacts artifacts: 'zap_report.html,zap_report.json,zap-counts.json', allowEmptyArchive: true
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

                // Try to read generated scan summaries (fallbacks handled)
                def trivyCounts = [:]
                if (fileExists('trivy-counts.json')) {
                    try { trivyCounts = readJSON file: 'trivy-counts.json' } catch (e) { trivyCounts = [:] }
                }
                def zapCounts = [:]
                if (fileExists('zap-counts.json')) {
                    try { zapCounts = readJSON file: 'zap-counts.json' } catch (e) { zapCounts = [:] }
                }
                def gitleaksFindings = 0
                if (fileExists('gitleaks-report.json')) {
                    try { gitleaksFindings = readJSON(file: 'gitleaks-report.json')?.size() ?: 0 } catch (e) { gitleaksFindings = 0 }
                }
                def semgrepFindings = 0
                if (fileExists('semgrep.json')) {
                    try { semgrepFindings = readJSON(file: 'semgrep.json')?.size() ?: 0 } catch (e) { semgrepFindings = 0 }
                }

                // Clean up containers and networks
                sh "docker rm -f ${env.CONTAINER_NAME} || true"
                sh "docker network rm ${env.NETWORK_NAME} || true"

                // Build comprehensive summary using real counts where available
                def summaryMessage = """
*${buildStatus}:* Job *${env.JOB_NAME}* Build #${env.BUILD_NUMBER}
👤 *Started by:* ${buildUser}
🔗 *Build URL:* <${env.BUILD_URL}|Click Here>

📊 *Security Scan Summary:*
   • 🔴 Critical Vulnerabilities: ${trivyCounts.Critical ?: 0}
   • 🟠 High Vulnerabilities: ${trivyCounts.High ?: 0}
   • 🟡 Medium Vulnerabilities: ${trivyCounts.Medium ?: 0}
   • Gitleaks Findings: ${gitleaksFindings}
   • Semgrep Findings: ${semgrepFindings}
   • ZAP High: ${zapCounts.high ?: 0}  ZAP Medium: ${zapCounts.medium ?: 0}

⚠️ *Note:* Configure FAIL_ON_CRITICAL_VULNS or FAIL_ON_HIGH_VULNS to change enforcement behavior
"""

                try {
                    slackSend(channel: '#devsecops', color: color, message: summaryMessage)
                } catch (e) {
                    echo "Slack failed: ${e}"
                }

                emailext (
                    subject: "Pipeline ${buildStatus}: ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                    body: """
                        <p>DevSecOps CI/CD pipeline report.</p>
                        <p>Project: ${env.JOB_NAME}</p>
                        <p>Build Number: ${env.BUILD_NUMBER}</p>
                        <p>Build Status: ${buildStatus}</p>
                        <p>Started by: ${buildUser}</p>
                        <p>Build URL: <a href="${env.BUILD_URL}">${env.BUILD_URL}</a></p>
                        <p>Security summary (attached): Critical=${trivyCounts.Critical ?: 0}, High=${trivyCounts.High ?: 0}, Medium=${trivyCounts.Medium ?: 0}</p>
                    """,
                    to: 'mekni.amin75@gmail.com',
                    from: 'mmekni66@gmail.com',
                    mimeType: 'text/html',
                    attachmentsPattern: 'trivy-fs.json,trivy-image.json,trivy-image.txt,target/dependency-check-report.xml,zap_report.html,zap_report.json,semgrep.json,gitleaks-report.json'
                )
            }
        }
    }
}
