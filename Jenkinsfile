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
                        script {
                            catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                                sh 'semgrep --config auto --output semgrep.json --json .'
                                def semgrepData = readJSON file: 'semgrep.json'
                                def criticalCount = semgrepData.results.count { it.severity in ['ERROR','CRITICAL'] }
                                def highCount = semgrepData.results.count { it.severity in ['WARNING','HIGH'] }
                                echo "Semgrep Summary: Critical=${criticalCount}, High=${highCount}"
                                archiveArtifacts artifacts: 'semgrep.json', allowEmptyArchive: true
                                if (criticalCount > 0 || highCount > 0) {
                                    error "Semgrep found Critical/High issues"
                                }
                            }
                        }
                    }
                }

                stage('SonarQube') {
                    steps {
                        script {
                            catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                                try {
                                    sh "${SCANNER_HOME}/bin/sonar-scanner -Dsonar.host.url=${env.SONAR_HOST_URL} -Dsonar.projectKey=vprofile -Dsonar.sources=src/ -Dsonar.java.binaries=target/classes -Dsonar.junit.reportsPath=target/surefire-reports -Dsonar.jacoco.reportPaths=target/jacoco.exec"
                                } catch (err) {
                                    echo "Sonar scanner failed: ${err}"
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
            steps {
                catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                    sh 'gitleaks detect --source . --report-format json --report-path gitleaks-report.json'
                    archiveArtifacts artifacts: 'gitleaks-report.json', allowEmptyArchive: true
                }
            }
        }

        stage('SCA & SBOM') {
            steps {
                catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                    sh 'mvn org.owasp:dependency-check-maven:check -Dformat=XML || true'
                    sh 'mvn org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom || true'
                    archiveArtifacts artifacts: 'target/dependency-check-report.xml,target/bom.*', allowEmptyArchive: true
                }
            }
        }

        stage('Trivy File Scan') {
            steps {
                catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                    sh 'trivy fs --format json -o trivy-fs.json .'
                    def trivyFs = readJSON file: 'trivy-fs.json'
                    def vulnerabilities = trivyFs.Vulnerabilities ?: []
                    def counts = [
                        Critical: vulnerabilities.count { it.Severity == 'CRITICAL' },
                        High:     vulnerabilities.count { it.Severity == 'HIGH' },
                        Medium:   vulnerabilities.count { it.Severity == 'MEDIUM' },
                        Low:      vulnerabilities.count { it.Severity == 'LOW' }
                    ]
                    echo "Trivy FS Summary: ${counts}"
                    writeFile file: 'trivy-fs-counts.json', text: groovy.json.JsonOutput.toJson(counts)
                    archiveArtifacts artifacts: 'trivy-fs.json,trivy-fs-counts.json', allowEmptyArchive: true
                    if (counts.Critical > 0 || counts.High > 0) {
                        error "Trivy FS found Critical/High vulnerabilities"
                    }
                }
            }
        }

        stage('Build Docker Image') {
            steps {
                script {
                    env.IMAGE_TAG = "${params.IMAGE_NAME}:${env.BUILD_NUMBER}"
                    catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
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

        stage('Trivy Image Scan') {
            steps {
                catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                    sh """
                        set -eu
                        docker image inspect ${env.IMAGE_TAG} > /dev/null 2>&1
                        trivy image -f json -o trivy-image.json ${env.IMAGE_TAG} || true
                        trivy image -f table -o trivy-image.txt ${env.IMAGE_TAG} || true
                    """
                    archiveArtifacts artifacts: 'trivy-image.json,trivy-image.txt', allowEmptyArchive: true
                }
            }
        }

        stage('Prepare Trivy Summary & Enforce Policy') {
            steps {
                script {
                    def trivyFile = 'trivy-image.json'
                    def vulnerabilities = []
                    if (fileExists(trivyFile)) {
                        def trivyJson = readJSON file: trivyFile
                        trivyJson.each { r ->
                            if (r instanceof Map && r.containsKey('Vulnerabilities')) {
                                vulnerabilities.addAll(r.Vulnerabilities ?: [])
                            }
                        }
                    }
                    def counts = [
                        Critical: vulnerabilities.count { it.Severity == 'CRITICAL' },
                        High:     vulnerabilities.count { it.Severity == 'HIGH' },
                        Medium:   vulnerabilities.count { it.Severity == 'MEDIUM' },
                        Low:      vulnerabilities.count { it.Severity == 'LOW' }
                    ]
                    echo "Trivy Image Summary: ${counts}"
                    writeFile file: 'trivy-counts.json', text: groovy.json.JsonOutput.toJson(counts)
                    archiveArtifacts artifacts: 'trivy-counts.json', allowEmptyArchive: true
                    if (counts.Critical > 0 || counts.High > 0) {
                        error "CRITICAL/HIGH vulnerabilities detected in Docker image"
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
                sh "docker network create vprofile-net || true"
                sh "docker rm -f vprofile || true"
                sh "docker run -d --name vprofile --network vprofile-net -p 8080:8080 ${env.IMAGE_TAG} || true"
            }
        }

        stage('DAST - OWASP ZAP') {
            steps {
                catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                    sh '''
                        docker run --rm --user root --network vprofile-net -v $(pwd):/zap/wrk:rw \
                        -t owasp/zap2docker-stable zap-baseline.py -t http://vprofile:8080 \
                        -r zap_report.html -J zap_report.json
                    '''
                    archiveArtifacts artifacts: 'zap_report.html,zap_report.json', allowEmptyArchive: true

                    def zapReport = readJSON file: 'zap_report.json'
                    def criticalAlerts = zapReport.site.collectMany { it.alerts }.count { it.risk == 3 }
                    echo "OWASP ZAP Critical Alerts: ${criticalAlerts}"
                    if (criticalAlerts > 0) {
                        error "OWASP ZAP found Critical issues"
                    }
                }
            }
        }

        stage('DevSecOps Combined Summary') {
            steps {
                script {
                    def summary = [:]

                    if (fileExists('trivy-fs-counts.json')) { summary['trivyFS'] = readJSON file: 'trivy-fs-counts.json' }
                    if (fileExists('trivy-counts.json')) { summary['trivyImage'] = readJSON file: 'trivy-counts.json' }

                    if (fileExists('semgrep.json')) {
                        def semgrepData = readJSON file: 'semgrep.json'
                        summary['semgrep'] = [ total: semgrepData.results.size(),
                                               criticalHigh: semgrepData.results.count { it.severity in ['ERROR','CRITICAL','WARNING','HIGH'] } ]
                    }

                    if (fileExists('zap_report.json')) {
                        def zapReport = readJSON file: 'zap_report.json'
                        summary['zap'] = [ criticalAlerts: zapReport.site.collectMany { it.alerts }.count { it.risk == 3 } ]
                    }

                    writeFile file: 'devsecops-summary.json', text: groovy.json.JsonOutput.prettyPrint(groovy.json.JsonOutput.toJson(summary))
                    archiveArtifacts artifacts: 'devsecops-summary.json', allowEmptyArchive: true
                    echo "DevSecOps summary generated and archived."
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
                        body: "<p>Build status: ${buildStatus}</p><p>Started by: ${buildUser}</p><p>Check artifacts (devsecops-summary.json, trivy-image.json, trivy-fs.json, zap_report.json, semgrep.json)</p>",
                        to: 'mekni.amin75@gmail.com',
                        from: 'mmekni66@gmail.com',
                        mimeType: 'text/html',
                        attachmentsPattern: 'devsecops-summary.json,trivy-image.json,trivy-fs.json,trivy-image.txt,zap_report.html,zap_report.json,semgrep.json,gitleaks-report.json,dependency-check-report.xml'
                    )
                } catch (e) { echo "Email failed: ${e}" }
            }
        }
    }
}
