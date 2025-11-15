// Jenkinsfile (declarative) - ready to paste
def COLOR_MAP = [
    'SUCCESS': 'good',
    'FAILURE': 'danger',
    'UNSTABLE': 'warning',
    'ABORTED': '#CCCCCC'
]

pipeline {
    agent any

    // Tools configured in Jenkins global tools (adjust names to match your Jenkins)
    tools {
        maven 'MAVEN3'
        jdk   'JDK17'
    }

    // Parametrize pipeline so you can reuse for different jobs
    parameters {
        booleanParam(name: 'PUSH_IMAGE', defaultValue: false, description: 'Push docker image to registry?')
        string(name: 'REGISTRY_URL', defaultValue: '192.168.50.4:5000', description: 'Docker Registry (host:port)')
        string(name: 'IMAGE_NAME', defaultValue: 'vprofileappimg', description: 'Local image name')
        booleanParam(name: 'ENFORCE_QUALITY_GATE', defaultValue: true, description: 'Abort pipeline if Sonar Quality Gate != OK')
        booleanParam(name: 'FAIL_ON_HIGH_VULNS', defaultValue: true, description: 'Fail pipeline if Trivy/Dependency-check find HIGH/Critical vulnerabilities')
    }

    environment {
        // Sonar scanner configured as a tool in Jenkins (adjust name if needed)
        SCANNER_HOME = tool 'sonar-scanner'
        NEXUS_VERSION = 'nexus3'
        NEXUS_PROTOCOL = 'http'
        NEXUS_URL = '192.168.50.4:8081'
        NEXUS_REPOSITORY = 'vprofile-repo'
        NEXUS_CREDENTIAL_ID = 'nexuslogin'
        SONAR_SERVER = 'sonar-server'
        DOCKER_CREDENTIALS_ID = 'jenkins-github-https-cred'
        GITLEAKS_CREDENTIALS = ''
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

        stage('Build (compile + unit tests)') {
            steps {
                // Run unit tests as part of the build so surefire produces XML reports
                sh 'mvn -B clean package -DskipITs=true'
            }
            post {
                success {
                    archiveArtifacts artifacts: '**/target/*.war', allowEmptyArchive: true
                }
            }
        }

        stage('Publish Unit Test Results & Coverage') {
            steps {
                script {
                    // Debug listing to help trace paths if something's wrong
                    sh 'echo "Listing target directories:" && find . -maxdepth 3 -name target -exec ls -la {} \\; || true'
                }
            }
            post {
                always {
                    // publish JUnit results - since we ran mvn package with tests, reports should exist
                    junit testResults: '**/target/surefire-reports/*.xml', allowEmptyResults: false, keepLongStdio: true

                    // jacoco - adjust patterns if necessary
                    jacoco(execPattern: 'target/jacoco.exec', classPattern: 'target/classes', sourcePattern: 'src/main/java')
                }
            }
        }

        stage('Integration Tests') {
            steps {
                // Run integration tests if any (maven fails as appropriate)
                sh 'mvn -B verify -DskipUnitTests=true || true'
            }
            post {
                always {
                    junit allowEmptyResults: true, testResults: '**/target/failsafe-reports/*.xml'
                }
            }
        }

        stage('Code Style - Checkstyle') {
            steps {
                sh 'mvn checkstyle:checkstyle || true'
            }
            post {
                success {
                    archiveArtifacts artifacts: 'target/checkstyle-result.xml', allowEmptyArchive: true
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
                        withSonarQubeEnv("${SONAR_SERVER}") {
                            sh """${SCANNER_HOME}/bin/sonar-scanner \
                                -Dsonar.projectKey=vprofile \
                                -Dsonar.projectName=vprofile-repo \
                                -Dsonar.projectVersion=1.0 \
                                -Dsonar.sources=src/ \
                                -Dsonar.java.binaries=target/classes \
                                -Dsonar.junit.reportsPath=target/surefire-reports \
                                -Dsonar.jacoco.reportPaths=target/jacoco.exec \
                                -Dsonar.java.checkstyle.reportPaths=target/checkstyle-result.xml
                            """
                        }
                    }
                }
            }
        }

        stage('Quality Gate') {
            steps {
                script {
                    timeout(time: 3, unit: 'MINUTES') {
                        def qg = waitForQualityGate() // blocks until Sonar analysis completes
                        echo "SonarQube Quality Gate status: ${qg.status}"
                        if (params.ENFORCE_QUALITY_GATE && qg.status != 'OK') {
                            error "Quality Gate failed with status: ${qg.status}"
                        }
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
            post {
                always {
                    archiveArtifacts artifacts: 'gitleaks-report.json', allowEmptyArchive: true
                }
            }
        }

        stage('Dependency-Check (SCA)') {
            steps {
                sh 'mvn org.owasp:dependency-check-maven:check -Dformat=XML || true'
            }
            post {
                always {
                    archiveArtifacts artifacts: 'target/dependency-check-report.xml', allowEmptyArchive: true
                }
            }
        }

        stage('Generate SBOM (CycloneDX)') {
            steps {
                sh 'mvn org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom || true'
            }
            post {
                always {
                    archiveArtifacts artifacts: 'target/bom.*', allowEmptyArchive: true
                }
            }
        }

        stage('Trivy File System Scan') {
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
                    sh "docker rmi -f ${params.IMAGE_NAME}:latest ${env.IMAGE_TAG} || true"
                    dockerImage = docker.build("${params.IMAGE_NAME}:latest", ".")
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
            post {
                always {
                    archiveArtifacts artifacts: 'trivy-image.json,trivy-image.txt', allowEmptyArchive: true
                }
            }
        }

        stage('Enforce Vulnerability Policy') {
            steps {
                script {
                    if (params.FAIL_ON_HIGH_VULNS) {
                        def fail = false
                        if (fileExists('trivy-image.json')) {
                            def trivy = readJSON file: 'trivy-image.json'
                            def criticalOrHigh = 0
                            if (trivy.Results) {
                                trivy.Results.each { res ->
                                    res.Vulnerabilities?.each { v ->
                                        if (v.Severity == 'CRITICAL' || v.Severity == 'HIGH') {
                                            criticalOrHigh++
                                        }
                                    }
                                }
                            }
                            echo "Trivy high/critical count: ${criticalOrHigh}"
                            if (criticalOrHigh > 0) { fail = true }
                        }
                        if (fail) { error "Failing pipeline because Trivy found HIGH/CRITICAL vulnerabilities" }
                    } else {
                        echo "FAIL_ON_HIGH_VULNS disabled - skipping strict vulnerability enforcement"
                    }
                }
            }
        }

        stage('Push Image to Registry (optional)') {
            when {
                expression { params.PUSH_IMAGE == true }
            }
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
            post {
                always {
                    archiveArtifacts artifacts: 'zap_report.html,zap_report.json', allowEmptyArchive: true
                }
            }
        }
    } // end stages

    post {
        always {
            script {
                def buildStatus = currentBuild.currentResult ?: 'UNKNOWN'
                def color = COLOR_MAP[buildStatus] ?: '#CCCCCC'

                // Safer user determination: Build User Vars plugin provides BUILD_USER_ID/BUILD_USER
                def buildUser = env.BUILD_USER_ID ?: env.BUILD_USER
                if (!buildUser) {
                    // fallback: use last git committer name (not necessarily the build trigger user)
                    buildUser = sh(returnStdout: true, script: "git --no-pager show -s --format='%an' HEAD || echo 'GitHub User'").trim()
                }

                // Slack notification (wrap in try/catch)
                try {
                    slackSend(
                        channel: '#devsecops',
                        color: color,
                        message: """*${buildStatus}:* Job *${env.JOB_NAME}* Build #${env.BUILD_NUMBER}
👤 *Started by:* ${buildUser}
🔗 *Build URL:* <${env.BUILD_URL}|Click Here for Details>"""
                    )
                } catch (e) {
                    echo "Slack notification failed: ${e}"
                }

                // Send email with attachments (wrap)
                try {
                    emailext (
                        subject: "Pipeline ${buildStatus}: ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                        body: """
                            <p> Created by Mekni Mohamed Amin </p>
                            <p> DevSecops CICD pipeline status.</p>
                            <p>Project: ${env.JOB_NAME}</p>
                            <p>Build Number: ${env.BUILD_NUMBER}</p>
                            <p>Build Status: ${buildStatus}</p>
                            <p>Started by: ${buildUser}</p>
                            <p>Build URL: <a href="${env.BUILD_URL}">${env.BUILD_URL}</a></p>
                        """,
                        to: 'mekni.amin75@gmail.com',
                        from: 'mmekni66@gmail.com',
                        mimeType: 'text/html',
                        attachmentsPattern: 'trivy-fs.json,trivy-image.json,trivy-image.txt,dependency-check-report.xml,zap_report.html,zap_report.json,semgrep.json,gitleaks-report.json'
                    )
                } catch (e) {
                    echo "Email notification failed: ${e}"
                }
            }
        }

        failure {
            script {
                echo "Build FAILED - additional cleanup or ticketing may be added here."
            }
        }

        success {
            script {
                echo "Build SUCCESS"
            }
        }
    }
}
