// Jenkinsfile - DevSecOps pipeline with Trivy enforcement and artifact archiving
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
        string(name: 'REGISTRY_URL', defaultValue: '192.168.50.4:5000', description: 'Docker Registry (host:port)')
        string(name: 'IMAGE_NAME', defaultValue: 'vprofileappimg', description: 'Local image name')
        booleanParam(name: 'ENFORCE_QUALITY_GATE', defaultValue: true, description: 'Abort pipeline if Sonar Quality Gate != OK')
    }

    environment {
        SONAR_HOST_URL = 'http://192.168.50.4:9000'
        SCANNER_HOME = tool 'sonar-scanner'
        DOCKER_CREDENTIALS_ID = 'jenkins-github-https-cred'
        ARTVERSION = "${env.BUILD_ID}"
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

        stage('Clean Workspace') { steps { cleanWs() } }

        stage('Checkout') {
            steps {
                checkout([$class: 'GitSCM',
                    branches: [[name: 'refs/heads/main']],
                    userRemoteConfigs: [[url: 'https://github.com/4tnx/devsecops.git']]
                ])
            }
        }

        stage('Build') {
            steps { sh 'mvn -B clean package -DskipITs=true' }
            post { success { archiveArtifacts artifacts: '**/target/*.war', allowEmptyArchive: true } }
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
                            def scannerCmd = "${SCANNER_HOME}/bin/sonar-scanner -Dsonar.host.url=${env.SONAR_HOST_URL} -Dsonar.projectKey=vprofile -Dsonar.sources=src/ -Dsonar.java.binaries=target/classes -Dsonar.junit.reportsPath=target/surefire-reports -Dsonar.jacoco.reportPaths=target/jacoco.exec"
                            try { sh scannerCmd } catch (err) { echo "Sonar scanner failed: ${err}"; sh "mvn -B sonar:sonar -Dsonar.host.url=${env.SONAR_HOST_URL} || true" }
                        }
                    }
                }
            }
        }

        stage('Quality Gate') {
            steps {
                script {
                    timeout(time: 3, unit: 'MINUTES') {
                        try {
                            def qg = waitForQualityGate()
                            echo "Quality Gate status: ${qg.status}"
                            if (params.ENFORCE_QUALITY_GATE && qg.status != 'OK') {
                                error "Quality Gate failed: ${qg.status}"
                            }
                        } catch (e) { echo "waitForQualityGate failed: ${e}" }
                    }
                }
            }
        }

        stage('Secrets Scan') {
            steps { sh 'gitleaks detect --source . --report-format json --report-path gitleaks-report.json || true' }
            post { always { archiveArtifacts artifacts: 'gitleaks-report.json', allowEmptyArchive: true } }
        }

        stage('SCA & SBOM') {
            steps {
                sh 'mvn org.owasp:dependency-check-maven:check -Dformat=XML || true'
                sh 'mvn org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom || true'
            }
            post {
                always { archiveArtifacts artifacts: 'target/dependency-check-report.xml,target/bom.*', allowEmptyArchive: true }
            }
        }

        stage('Trivy File Scan') {
            steps { sh 'trivy fs --exit-code 0 --format json -o trivy-fs.json . || true' }
            post { always { archiveArtifacts artifacts: 'trivy-fs.json', allowEmptyArchive: true } }
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
                                docker build --network host --progress=plain --pull --cache-from ${IMAGE_NAME}:latest -t ${IMAGE_NAME}:latest .
                                docker tag ${IMAGE_NAME}:latest ${IMAGE_TAG}
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
                        trivy image -f json -o trivy-image.json ${env.IMAGE_TAG} || true
                        trivy image -f table -o trivy-image.txt ${env.IMAGE_TAG} || true
                    """
                }
            }
            post { always { archiveArtifacts artifacts: 'trivy-image.json,trivy-image.txt', allowEmptyArchive: true } }
        }

    stage('Prepare Trivy Summary & Enforce Policy') {
    steps {
        script {
            // --- Read Trivy JSON safely ---
            def trivyFile = 'trivy-image.json'
            def vulnerabilities = []

            if (fileExists(trivyFile)) {
                def trivyJson = readJSON file: trivyFile

                // Loop through top-level elements safely
                trivyJson.each { r ->
                    if (r instanceof Map && r.containsKey('Vulnerabilities')) {
                        vulnerabilities.addAll(r.Vulnerabilities ?: [])
                    }
                }
            } else {
                echo "Trivy JSON file not found: ${trivyFile}"
            }

            // --- Count vulnerabilities by severity ---
            def counts = [
                Critical: vulnerabilities.count { it.Severity == 'CRITICAL' },
                High:     vulnerabilities.count { it.Severity == 'HIGH' },
                Medium:   vulnerabilities.count { it.Severity == 'MEDIUM' },
                Low:      vulnerabilities.count { it.Severity == 'LOW' }
            ]

            // --- Print summary ---
            echo "Trivy Summary:"
            counts.each { k, v ->
                echo "${k}: ${v}"
            }

            // --- Save summary to file (optional) ---
            writeFile file: 'trivy-counts.json', text: groovy.json.JsonOutput.toJson(counts)
            archiveArtifacts artifacts: 'trivy-counts.json', allowEmptyArchive: true

            // --- Print top 20 vulnerabilities ---
            if (vulnerabilities.size() > 0) {
                echo "Top 20 vulnerabilities (severity | pkg | installed | fixed | vuln):"
                vulnerabilities.sort { a, b ->
                    // Sort by severity: CRITICAL > HIGH > MEDIUM > LOW
                    def severityOrder = ['CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1]
                    return (severityOrder[b.Severity] ?: 0) <=> (severityOrder[a.Severity] ?: 0)
                }.take(20).each { vuln ->
                    echo "${vuln.Severity} | ${vuln.PkgName} | ${vuln.InstalledVersion ?: '-'} | ${vuln.FixedVersion ?: '-'} | ${vuln.VulnerabilityID}"
                }
            } else {
                echo "No vulnerabilities found in Trivy scan."
            }

            // --- Enforce Vulnerability Policy ---
            if (counts.Critical > 0 || counts.High > 0) {
                error "Pipeline FAILED: CRITICAL/HIGH vulnerabilities detected (Critical=${counts.Critical}, High=${counts.High})"
            } else {
                echo "Vulnerability policy passed."
            }
        }
    }
}


        stage('Enforce Vulnerability Policy') {
            steps {
                script {
                    if (fileExists('trivy-image.json')) {
                        def trivyJson = readJSON file: 'trivy-image.json'
                        def high = 0
                        def critical = 0
                        trivyJson.each { result ->
                            result.Vulnerabilities?.each { vuln ->
                                if (vuln.Severity == 'HIGH') { high++ }
                                else if (vuln.Severity == 'CRITICAL') { critical++ }
                            }
                        }
                        echo "Trivy HIGH vulnerabilities: ${high}"
                        echo "Trivy CRITICAL vulnerabilities: ${critical}"

                        if (critical > 0 || high > 0) {
                            error "Pipeline FAILED: CRITICAL vulnerabilities detected (${critical})"
                        }
                    } else {
                        echo "No trivy-image.json found, skipping enforcement."
                    }
                }
            }
        }

        stage('Push Image to Registry') {
            when { expression { params.PUSH_IMAGE } }
            steps {
                script {
                    docker.withRegistry("https://${params.REGISTRY_URL}", "${DOCKER_CREDENTIALS_ID}") {
                        sh "docker push ${env.IMAGE_TAG} || true"
                        sh "docker push ${params.IMAGE_NAME}:latest || true"
                    }
                }
            }
        }

        stage('Deploy Container') {
            steps {
                script {
                    sh "docker network create vprofile-net || true"
                    sh "docker rm -f vprofile || true"
                    sh "docker run -d --name vprofile --network vprofile-net -p 8080:8080 ${env.IMAGE_TAG} || true"
                }
            }
        }

       stage("DAST Scan with OWASP ZAP") {
            steps {
                script {
                    echo '🔍 Running OWASP ZAP baseline scan...'

                    // Run ZAP but ignore exit code
                    def exitCode = sh(script: '''
                        docker run --rm --user root --network host -v $(pwd):/zap/wrk:rw \
                        -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py \
                        -t http://localhost \
                        -r zap_report.html -J zap_report.json
                    ''', returnStatus: true)

                    echo "ZAP scan finished with exit code: ${exitCode}"

                    // Read the JSON report if it exists
                    if (fileExists('zap_report.json')) {
                        def zapJson = readJSON file: 'zap_report.json'

                        def highCount = zapJson.site.collect { site ->
                            site.alerts.findAll { it.risk == 'High' }.size()
                        }.sum()

                        def mediumCount = zapJson.site.collect { site ->
                            site.alerts.findAll { it.risk == 'Medium' }.size()
                        }.sum()

                        def lowCount = zapJson.site.collect { site ->
                            site.alerts.findAll { it.risk == 'Low' }.size()
                        }.sum()

                        echo "✅ High severity issues: ${highCount}"
                        echo "⚠️ Medium severity issues: ${mediumCount}"
                        echo "ℹ️ Low severity issues: ${lowCount}"
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
                if (!buildUser) { buildUser = sh(returnStdout: true, script: "git --no-pager show -s --format='%an' HEAD || echo 'GitHub User'").trim() }

                try {
                    slackSend(channel: '#devsecops', color: color, message: """*${buildStatus}:* Job *${env.JOB_NAME}* Build #${env.BUILD_NUMBER}
👤 *Started by:* ${buildUser}
🔗 *Build URL:* <${env.BUILD_URL}|Click Here>""")
                } catch (e) { echo "Slack failed: ${e}" }

                try {
                    emailext(
                        subject: "Pipeline ${buildStatus}: ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                        body: "<p>Build status: ${buildStatus}</p><p>Started by: ${buildUser}</p><p>Check artifacts (trivy-summary.txt, trivy-image.json)</p>",
                        to: 'mekni.amin75@gmail.com',
                        from: 'mmekni66@gmail.com',
                        mimeType: 'text/html',
                        attachmentsPattern: 'trivy-summary.txt,trivy-image.json,trivy-image.txt,dependency-check-report.xml,zap_report.html,zap_report.json,semgrep.json,gitleaks-report.json'
                    )
                } catch (e) { echo "Email failed: ${e}" }
            }
        }
    }
}
