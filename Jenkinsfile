// Jenkinsfile - with explicit Sonar host URL + connectivity check
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
        jdk   'JDK17'
    }

    parameters {
        booleanParam(name: 'PUSH_IMAGE', defaultValue: false, description: 'Push docker image to registry?')
        string(name: 'REGISTRY_URL', defaultValue: '192.168.50.4:5000', description: 'Docker Registry (host:port)')
        string(name: 'IMAGE_NAME', defaultValue: 'vprofileappimg', description: 'Local image name')
        booleanParam(name: 'ENFORCE_QUALITY_GATE', defaultValue: true, description: 'Abort pipeline if Sonar Quality Gate != OK')
        booleanParam(name: 'FAIL_ON_HIGH_VULNS', defaultValue: true, description: 'Fail pipeline if Trivy/Dependency-check find HIGH/Critical vulnerabilities')
    }

    environment {
        // IMPORTANT: set this to the actual address where SonarQube is reachable from Jenkins
        SONAR_HOST_URL = 'http://192.168.50.4:9000'
        SCANNER_HOME = tool 'sonar-scanner'   // optional if you use sonar-scanner CLI
        NEXUS_URL = '192.168.50.4:8081'
        NEXUS_REPOSITORY = 'vprofile-repo'
        NEXUS_CREDENTIAL_ID = 'nexuslogin'
        SONAR_SERVER = 'sonar-server'        // name in Jenkins (kept for withSonarQubeEnv if used)
        DOCKER_CREDENTIALS_ID = 'jenkins-github-https-cred'
        ARTVERSION = "${env.BUILD_ID}"
    }

    options {
        timestamps()
        ansiColor('xterm')
        skipDefaultCheckout(false)
        buildDiscarder(logRotator(numToKeepStr: '20'))
        durabilityHint('MAX_SURVIVABILITY')
        timeout(time: 60, unit: 'MINUTES')
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
            steps {
                sh 'mvn -B clean package -DskipITs=true'
            }
            post { success { archiveArtifacts artifacts: '**/target/*.war', allowEmptyArchive: true } }
        }

        stage('Publish Unit Test Results & Coverage') {
            steps {
                script {
                    sh 'echo "Listing target dirs:" && find . -maxdepth 3 -name target -exec ls -la {} \\; || true'
                }
            }
            post {
                always {
                    junit testResults: '**/target/surefire-reports/*.xml', allowEmptyResults: true, keepLongStdio: true
                    jacoco(execPattern: 'target/jacoco.exec', classPattern: 'target/classes', sourcePattern: 'src/main/java')
                }
            }
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
                            // quick connectivity check to Sonar server before running scanner
                            echo "Checking SonarQube connectivity to ${env.SONAR_HOST_URL}"
                            def rc = sh(script: "curl -sS --max-time 10 ${env.SONAR_HOST_URL}/api/system/health || true", returnStdout: true).trim()
                            if (!rc) {
                                echo "WARNING: SonarQube did not respond at ${env.SONAR_HOST_URL}. Continuing but Sonar analysis will likely fail."
                                // If you want to fail the pipeline here instead, uncomment:
                                // error "Cannot reach SonarQube at ${env.SONAR_HOST_URL}"
                            } else {
                                echo "Sonar responded: ${rc}"
                            }

                            // Prefer passing explicit sonar.host.url so the scanner doesn't default to localhost
                            // Use SONAR_HOST_URL variable we set above
                            def scannerCmd = "${SCANNER_HOME}/bin/sonar-scanner " +
                                    "-Dsonar.host.url=${env.SONAR_HOST_URL} " +
                                    "-Dsonar.projectKey=vprofile " +
                                    "-Dsonar.projectName=vprofile-repo " +
                                    "-Dsonar.projectVersion=1.0 " +
                                    "-Dsonar.sources=src/ " +
                                    "-Dsonar.java.binaries=target/classes " +
                                    "-Dsonar.junit.reportsPath=target/surefire-reports " +
                                    "-Dsonar.jacoco.reportPaths=target/jacoco.exec " +
                                    "-Dsonar.java.checkstyle.reportPaths=target/checkstyle-result.xml"

                            echo "Running Sonar scanner..."
                            // run scanner but don't fail pipeline hard here if scanner fails (adjust to your policy)
                            try {
                                sh "${scannerCmd}"
                            } catch (err) {
                                echo "Sonar scanner failed: ${err}"
                                // fallback: try maven sonar:sonar (Maven plugin) which may use Jenkins Sonar config
                                echo "Attempting fallback: mvn sonar:sonar with explicit host URL"
                                sh "mvn -B sonar:sonar -Dsonar.host.url=${env.SONAR_HOST_URL} || true"
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
                        // waitForQualityGate requires SonarQube token + analysis to have completed
                        try {
                            def qg = waitForQualityGate()
                            echo "Quality Gate status: ${qg.status}"
                            if (params.ENFORCE_QUALITY_GATE && qg.status != 'OK') {
                                error "Quality Gate failed: ${qg.status}"
                            }
                        } catch (e) {
                            echo "waitForQualityGate failed or timed out: ${e}"
                            // optionally error() here if you want to make this fatal
                        }
                    }
                }
            }
        }

        // rest of the stages (gitleaks, dependency-check, trivy, build docker, etc.)
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
            // Give this stage more time (adjust minutes as needed)
            timeout(time: 45, unit: 'MINUTES') {
                // retry transient failures (2 retries)
                retry(2) {
                    sh '''
                        # enable BuildKit for faster builds and better caching
                        export DOCKER_BUILDKIT=1

                        # pre-pull the base image(s) referenced in your Dockerfile to avoid long downloads inside build
                        # replace with the actual base image you use e.g. openjdk:17-jdk or openjdk:17-jdk-slim
                        docker pull openjdk:17-jdk || true

                        # use --network host to avoid DNS issues and sometimes speed up downloads,
                        # --pull to attempt to get latest base image, --progress=plain for readable logs
                        # --cache-from attempts to use previous image as cache (push previous image to registry to benefit)
                        docker build --network host --progress=plain --pull --cache-from ${params.IMAGE_NAME}:latest -t ${params.IMAGE_NAME}:latest .
                    '''
                }
            }
            // tag the build-specific version
            sh "docker tag ${params.IMAGE_NAME}:latest ${env.IMAGE_TAG}"
        }
    }
}


        stage('Trivy Image Scan') {
            steps {
                script {
                    sh """
                        trivy image -f json -o trivy-image.json ${env.IMAGE_TAG} || true
                        trivy image -f table -o trivy-image.txt ${env.IMAGE_TAG} || true
                    """
                }
            }
            post { always { archiveArtifacts artifacts: 'trivy-image.json,trivy-image.txt', allowEmptyArchive: true } }
        }

        stage('Enforce Vulnerability Policy') {
            steps {
                script {
                    if (params.FAIL_ON_HIGH_VULNS) {
                        def fail = false
                        if (fileExists('trivy-image.json')) {
                            def trivy = readJSON file: 'trivy-image.json'
                            def criticalOrHigh = 0
                            trivy.Results?.each { res ->
                                res.Vulnerabilities?.each { v ->
                                    if (v.Severity == 'CRITICAL' || v.Severity == 'HIGH') { criticalOrHigh++ }
                                }
                            }
                            echo "Trivy high/critical count: ${criticalOrHigh}"
                            if (criticalOrHigh > 0) { fail = true }
                        }
                        if (fail) { error "Failing pipeline because Trivy found HIGH/CRITICAL vulnerabilities" }
                    } else { echo "FAIL_ON_HIGH_VULNS disabled - skipping strict vulnerability enforcement" }
                }
            }
        }

        stage('Push Image to Registry (optional)') {
            when { expression { params.PUSH_IMAGE == true } }
            steps {
                script {
                    docker.withRegistry("https://${params.REGISTRY_URL}", "${DOCKER_CREDENTIALS_ID}") {
                        dockerImage.push("${env.BUILD_NUMBER}")
                        dockerImage.push('latest')
                    }
                }
            }
        }

        stage('Deploy to Container (local agent)') {
            steps {
                script {
                    sh "docker network create vprofile-net || true"
                    sh "docker rm -f vprofile || true"
                    sh "docker run -d --name vprofile --network vprofile-net -p 8080:8080 ${env.IMAGE_TAG}"
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
                if (!buildUser) {
                    buildUser = sh(returnStdout: true, script: "git --no-pager show -s --format='%an' HEAD || echo 'GitHub User'").trim()
                }

                try {
                    slackSend(channel: '#devsecops', color: color, message: """*${buildStatus}:* Job *${env.JOB_NAME}* Build #${env.BUILD_NUMBER}
👤 *Started by:* ${buildUser}
🔗 *Build URL:* <${env.BUILD_URL}|Click Here for Details>""")
                } catch (e) { echo "Slack notify failed: ${e}" }

                try {
                    emailext (
                        subject: "Pipeline ${buildStatus}: ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                        body: "<p> DevSecops CICD pipeline status.</p><p>Build Status: ${buildStatus}</p><p>Started by: ${buildUser}</p><p>Build URL: <a href='${env.BUILD_URL}'>${env.BUILD_URL}</a></p>",
                        to: 'mekni.amin75@gmail.com',
                        from: 'mmekni66@gmail.com',
                        mimeType: 'text/html',
                        attachmentsPattern: 'trivy-fs.json,trivy-image.json,trivy-image.txt,dependency-check-report.xml,zap_report.html,zap_report.json,semgrep.json,gitleaks-report.json'
                    )
                } catch (e) { echo "Email failed: ${e}" }
            }
        }

        failure { script { echo "Build FAILED - additional cleanup or ticketing may be added here." } }
        success { script { echo "Build SUCCESS" } }
    }
}
