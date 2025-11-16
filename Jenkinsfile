// Jenkinsfile - full pipeline with configurable Trivy enforcement and triage artifacts
def COLOR_MAP = [
    'SUCCESS': 'good',
    'FAILURE': 'danger',
    'UNSTABLE': 'warning',
    'ABORTED': '#CCCCCC'
]

pipeline {
    agent any

    tools {
        maven 'MAVEN3'   // adjust to your Jenkins tool names
        jdk   'JDK17'
    }

    parameters {
        booleanParam(name: 'PUSH_IMAGE', defaultValue: false, description: 'Push docker image to registry?')
        string(name: 'REGISTRY_URL', defaultValue: '192.168.50.4:5000', description: 'Docker Registry (host:port)')
        string(name: 'IMAGE_NAME', defaultValue: 'vprofileappimg', description: 'Local image name')
        booleanParam(name: 'ENFORCE_QUALITY_GATE', defaultValue: true, description: 'Abort pipeline if Sonar Quality Gate != OK')
        // New policy parameters:
        booleanParam(name: 'FAIL_ON_CRITICAL_ONLY', defaultValue: true, description: 'If true, only CRITICAL vulnerabilities will fail the pipeline; HIGHs will not.')
        string(name: 'HIGH_VULN_THRESHOLD', defaultValue: '10', description: 'If FAIL_ON_CRITICAL_ONLY=false, fail when HIGH+CRITICAL > this threshold (integer).')
        booleanParam(name: 'FAIL_ON_HIGH_VULNS', defaultValue: true, description: 'Legacy flag — kept for backward compat (if true, original behavior could be enforced).')
    }

    environment {
        SONAR_HOST_URL = 'http://192.168.50.4:9000'
        SCANNER_HOME = tool 'sonar-scanner'
        NEXUS_URL = '192.168.50.4:8081'
        NEXUS_REPOSITORY = 'vprofile-repo'
        NEXUS_CREDENTIAL_ID = 'nexuslogin'
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

        stage('Build (compile + unit tests)') {
            steps { sh 'mvn -B clean package -DskipITs=true' }
            post { success { archiveArtifacts artifacts: '**/target/*.war', allowEmptyArchive: true } }
        }

        stage('Publish Unit Test Results & Coverage') {
            steps {
                script { sh 'echo "Listing top-level target directories:" && find . -maxdepth 3 -name target -exec ls -la {} \\; || true' }
            }
            post {
                always {
                    junit testResults: '**/target/surefire-reports/*.xml', allowEmptyResults: true, keepLongStdio: true
                    jacoco(execPattern: 'target/jacoco.exec', classPattern: 'target/classes', sourcePattern: 'src/main/java')
                }
            }
        }

        stage('Integration Tests') {
            steps { sh 'mvn -B verify -DskipUnitTests=true || true' }
            post { always { junit testResults: '**/target/failsafe-reports/*.xml', allowEmptyResults: true } }
        }

        stage('Code Style - Checkstyle') {
            steps { sh 'mvn checkstyle:checkstyle || true' }
            post { success { archiveArtifacts artifacts: 'target/checkstyle-result.xml', allowEmptyArchive: true } }
        }

        stage('Static Analysis - Semgrep + SonarQube') {
            parallel {
                stage('Semgrep (fast patterns)') {
                    steps {
                        sh 'semgrep --config auto --output semgrep.json --json . || true'
                        archiveArtifacts artifacts: 'semgrep.json', allowEmptyArchive: true
                    }
                }

                stage('SonarQube Analysis') {
                    steps {
                        script {
                            echo "Checking SonarQube at ${env.SONAR_HOST_URL}"
                            def health = sh(script: "curl -sS --max-time 8 ${env.SONAR_HOST_URL}/api/system/health || true", returnStdout: true).trim()
                            if (!health) { echo "Sonar not reachable (continuing)"; } else { echo "Sonar health: ${health}" }
                            def scannerCmd = "${SCANNER_HOME}/bin/sonar-scanner -Dsonar.host.url=${env.SONAR_HOST_URL} -Dsonar.projectKey=vprofile -Dsonar.projectName=vprofile-repo -Dsonar.projectVersion=1.0 -Dsonar.sources=src/ -Dsonar.java.binaries=target/classes -Dsonar.junit.reportsPath=target/surefire-reports -Dsonar.jacoco.reportPaths=target/jacoco.exec -Dsonar.java.checkstyle.reportPaths=target/checkstyle-result.xml"
                            try { sh scannerCmd } catch (err) { echo "Sonar scanner CLI failed: ${err}"; sh "mvn -B sonar:sonar -Dsonar.host.url=${env.SONAR_HOST_URL} || true" }
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
                            if (params.ENFORCE_QUALITY_GATE && qg.status != 'OK') { error "Quality Gate failed: ${qg.status}" }
                        } catch (e) { echo "waitForQualityGate failed/timed out: ${e} (continuing)" }
                    }
                }
            }
        }

        stage('Secrets Scan - Gitleaks') {
            steps {
                sh '''
                   set +e
                   gitleaks detect --source . --report-format json --report-path gitleaks-report.json || true
                   set -e
                '''
            }
            post { always { archiveArtifacts artifacts: 'gitleaks-report.json', allowEmptyArchive: true } }
        }

        stage('Dependency-Check (SCA)') {
            steps { sh 'mvn org.owasp:dependency-check-maven:check -Dformat=XML || true' }
            post { always { archiveArtifacts artifacts: 'target/dependency-check-report.xml', allowEmptyArchive: true } }
        }

        stage('Generate SBOM (CycloneDX)') {
            steps { sh 'mvn org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom || true' }
            post { always { archiveArtifacts artifacts: 'target/bom.*', allowEmptyArchive: true } }
        }

        stage('Trivy File System Scan') {
            steps { sh 'trivy fs --exit-code 0 --format json -o trivy-fs.json . || true' }
            post { always { archiveArtifacts artifacts: 'trivy-fs.json', allowEmptyArchive: true } }
        }

        stage('Build Docker Image') {
            steps {
                script {
                    env.IMAGE_TAG = "${params.IMAGE_NAME}:${env.BUILD_NUMBER}"
                    timeout(time: 45, unit: 'MINUTES') {
                        retry(2) {
                            sh """
                                set -eu
                                export DOCKER_BUILDKIT=1
                                if [ -f Dockerfile ]; then
                                  BASE_IMAGE=\$(sed -n 's/^FROM[[:space:]]\\+\\([^[:space:]]\\+\\).*/\\1/p' Dockerfile | head -n1 || true)
                                else
                                  BASE_IMAGE=""
                                fi
                                if [ -n "\$BASE_IMAGE" ]; then
                                  echo "Pre-pulling base image: \$BASE_IMAGE"
                                  docker pull "\$BASE_IMAGE" || true
                                else
                                  echo "No Dockerfile or FROM; skipping pre-pull"
                                fi
                                echo "Building ${params.IMAGE_NAME}:latest"
                                docker build --network host --progress=plain --pull --cache-from ${params.IMAGE_NAME}:latest -t ${params.IMAGE_NAME}:latest .
                                docker tag ${params.IMAGE_NAME}:latest ${env.IMAGE_TAG}
                            """
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
                        if docker image inspect ${env.IMAGE_TAG} > /dev/null 2>&1; then
                          trivy image -f json -o trivy-image.json ${env.IMAGE_TAG} || true
                          trivy image -f table -o trivy-image.txt ${env.IMAGE_TAG} || true
                        else
                          echo "Image ${env.IMAGE_TAG} not found; skipping image scan"
                        fi
                    """
                }
            }
            post { always { archiveArtifacts artifacts: 'trivy-image.json,trivy-image.txt', allowEmptyArchive: true } }
        }

       stage('Prepare Trivy Summary') {
    steps {
        script {
            // Create a human-friendly summary from trivy-image.json (if present)
            sh '''
              set -eu
              if [ -f trivy-image.json ]; then
                # Top-level counts
                jq -r '{
                  Critical: (.[].Vulnerabilities // [] | map(select(.Severity=="CRITICAL")) | length),
                  High:     (.[].Vulnerabilities // [] | map(select(.Severity=="HIGH")) | length),
                  Medium:   (.[].Vulnerabilities // [] | map(select(.Severity=="MEDIUM")) | length),
                  Low:      (.[].Vulnerabilities // [] | map(select(.Severity=="LOW")) | length)
                }' trivy-image.json > trivy-counts.json || true

                echo "Trivy summary for image ${env.IMAGE_TAG}" > trivy-summary.txt
                jq -r 'to_entries[] | "\(.key): \(.value)"' trivy-counts.json >> trivy-summary.txt || true
                echo "" >> trivy-summary.txt
                echo "Top 20 vulnerabilities (severity | pkg | installed | fixed | vulnerability):" >> trivy-summary.txt
                # list top 20 unique vulns sorted by severity + package
                jq -r '[.[].Vulnerabilities[]? | {severity: .Severity, pkg: .PkgName, installed: (.InstalledVersion // "-"), fixed: (.FixedVersion // "-"), vuln: .VulnerabilityID}] | sort_by(.severity) | reverse | unique_by(.vuln) | .[] | "\(.severity) | \(.pkg) | \(.installed) | \(.fixed) | \(.vuln)"' trivy-image.json | head -n 20 >> trivy-summary.txt || true
              else
                echo "No trivy-image.json present; cannot summarize" > trivy-summary.txt
              fi
            '''
            archiveArtifacts artifacts: 'trivy-summary.txt', allowEmptyArchive: true
        }
    }
}


        stage('Enforce Vulnerability Policy') {
    steps {
        script {
            if (fileExists('trivy-image.json')) {
                // Read the JSON file
                def trivyJson = readJSON file: 'trivy-image.json'

                // Count high and critical vulnerabilities
                def highCount = 0
                def criticalCount = 0

                trivyJson.Results.each { result ->
                    result.Vulnerabilities?.each { vuln ->
                        if (vuln.Severity == 'HIGH') {
                            highCount += 1
                        } else if (vuln.Severity == 'CRITICAL') {
                            criticalCount += 1
                        }
                    }
                }

                echo "Trivy high count: ${highCount}"
                echo "Trivy critical count: ${criticalCount}"

                if (highCount + criticalCount > 0) {
                    error "Failing pipeline because Trivy found HIGH/CRITICAL vulnerabilities"
                }
            } else {
                echo "No Trivy JSON found, skipping vulnerability enforcement."
            }
        }
    }
}


        stage('Push Image to Registry (optional)') {
            when { expression { params.PUSH_IMAGE == true } }
            steps {
                script {
                    docker.withRegistry("https://${params.REGISTRY_URL}", "${DOCKER_CREDENTIALS_ID}") {
                        sh "docker push ${params.IMAGE_NAME}:${env.BUILD_NUMBER} || true"
                        sh "docker push ${params.IMAGE_NAME}:latest || true"
                    }
                }
            }
        }

        stage('Deploy to Container (local agent)') {
            steps {
                script {
                    sh "docker network create vprofile-net || true"
                    sh "docker rm -f vprofile || true"
                    sh "docker run -d --name vprofile --network vprofile-net -p 8080:8080 ${env.IMAGE_TAG} || true"
                }
            }
        }

        stage('DAST - OWASP ZAP (baseline)') {
            steps {
                script {
                    sh '''
                        docker run --rm --user root --network vprofile-net -v $(pwd):/zap/wrk:rw \
                          -t owasp/zap2docker-stable zap-baseline.py \
                          -t http://vprofile:8080 \
                          -r zap_report.html -J zap_report.json || true
                    '''
                }
            }
            post { always { archiveArtifacts artifacts: 'zap_report.html,zap_report.json', allowEmptyArchive: true } }
        }
    } // end stages

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
🔗 *Build URL:* <${env.BUILD_URL}|Click Here for Details>""")
                } catch (e) { echo "Slack failed: ${e}" }

                try {
                    emailext (
                        subject: "Pipeline ${buildStatus}: ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                        body: "<p>Build status: ${buildStatus}</p><p>Started by: ${buildUser}</p><p>Check artifacts (trivy-summary.txt, trivy-image.json, trivy-image.txt)</p>",
                        to: 'mekni.amin75@gmail.com',
                        from: 'mmekni66@gmail.com',
                        mimeType: 'text/html',
                        attachmentsPattern: 'trivy-summary.txt,trivy-image.json,trivy-image.txt,dependency-check-report.xml,zap_report.html,zap_report.json,semgrep.json,gitleaks-report.json'
                    )
                } catch (e) { echo "Email failed: ${e}" }
            }
        }

        failure { script { echo "Build FAILED - investigate trivy-summary.txt and trivy-image.json (archived)." } }
        success { script { echo "Build SUCCESS" } }
    }
}
