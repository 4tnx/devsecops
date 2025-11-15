def COLOR_MAP = [
    'SUCCESS': 'good',
    'FAILURE': 'danger',
]

pipeline {
    agent any
    tools {
        maven 'MAVEN3'
        jdk 'JDK17'
    }
    environment {
        SCANNER_HOME = tool 'sonar-scanner'

        // Nexus settings (unchanged)
        NEXUS_VERSION = 'nexus3'
        NEXUS_PROTOCOL = "http"
        NEXUS_URL = "192.168.50.4:8081"
        NEXUS_REPOSITORY = "vprofile-repo"
        NEXUS_REPO_ID = "vprofile-repo"
        NEXUS_CREDENTIAL_ID = "nexuslogin"
        ARTVERSION = "${env.BUILD_ID}"

        // Local Docker image name (no registry)
        IMAGE_NAME = 'vprofileappimg'
    }

    stages {
        stage("Clean Workspace") { steps { cleanWs() } }

        stage("Git Checkout") {
            steps {
                git branch: 'main', url: 'https://github.com/harishnshetty/maven-devsecops-ecr-project.git'
            }
        }

        stage('BUILD') {
            steps { sh 'mvn clean install -DskipTests' }
            post { success { echo 'Now Archiving...'; archiveArtifacts artifacts: '**/target/*.war' } }
        }

        stage('UNIT TEST') { steps { sh 'mvn test' } }

        stage('INTEGRATION TEST') { steps { sh 'mvn verify -DskipUnitTests' } }

        stage('CODE ANALYSIS WITH CHECKSTYLE') {
            steps { sh 'mvn checkstyle:checkstyle' }
            post { success { echo 'Generated Analysis Result' } }
        }

        stage('CODE ANALYSIS with SONARQUBE') {
            steps {
                withSonarQubeEnv('sonar-server') {
                    sh '''${SCANNER_HOME}/bin/sonar-scanner -Dsonar.projectKey=vprofile \
                        -Dsonar.projectName=vprofile-repo \
                        -Dsonar.projectVersion=1.0 \
                        -Dsonar.sources=src/ \
                        -Dsonar.java.binaries=target/test-classes/com/visualpathit/account/controllerTest/ \
                        -Dsonar.junit.reportsPath=target/surefire-reports/ \
                        -Dsonar.jacoco.reportsPath=target/jacoco.exec \
                        -Dsonar.java.checkstyle.reportPaths=target/checkstyle-result.xml'''
                }
            }
        }

        stage("Quality Gate") {
            steps {
                script {
                    timeout(time: 3, unit: 'MINUTES') {
                        waitForQualityGate abortPipeline: false, credentialsId: 'sonarqube'
                    }
                }
            }
        }

        stage("Publish to Nexus Repository Manager") {
            steps {
                script {
                    pom = readMavenPom file: "pom.xml"
                    filesByGlob = findFiles(glob: "target/*.${pom.packaging}")
                    echo "${filesByGlob[0].name} ${filesByGlob[0].path}"
                    artifactPath = filesByGlob[0].path
                    artifactExists = fileExists artifactPath
                    if (artifactExists) {
                        nexusArtifactUploader(
                            nexusVersion: NEXUS_VERSION,
                            protocol: NEXUS_PROTOCOL,
                            nexusUrl: NEXUS_URL,
                            groupId: pom.groupId,
                            version: ARTVERSION,
                            repository: NEXUS_REPOSITORY,
                            credentialsId: NEXUS_CREDENTIAL_ID,
                            artifacts: [
                                [artifactId: pom.artifactId, classifier: '', file: artifactPath, type: pom.packaging],
                                [artifactId: pom.artifactId, classifier: '', file: "pom.xml", type: "pom"]
                            ]
                        )
                    } else {
                        error "*** File: ${artifactPath}, could not be found"
                    }
                }
            }
        }

        stage("OWASP Dependency Check Scan") {
            steps {
                dependencyCheck additionalArguments: '''
                    --scan .
                    --disableYarnAudit
                    --disableNodeAudit
                ''', odcInstallation: 'dp-check'
                dependencyCheckPublisher pattern: '**/dependency-check-report.xml'
            }
        }

        stage("Trivy File Scan") {
            steps { sh "trivy fs . > trivyfs.txt" }
        }

        stage("Build Docker Image") {
            steps {
                script {
                    // Build and tag locally
                    env.IMAGE_TAG = "${IMAGE_NAME}:${BUILD_NUMBER}"
                    sh "docker rmi -f ${IMAGE_NAME}:latest ${env.IMAGE_TAG} || true"
                    dockerImage = docker.build("${IMAGE_NAME}:latest", ".")
                    sh "docker tag ${IMAGE_NAME}:latest ${env.IMAGE_TAG}"
                }
            }
        }

        stage("Trivy Scan Image") {
            steps {
                script {
                    sh """
                    echo '🔍 Running Trivy scan on ${env.IMAGE_TAG}'
                    trivy image -f json -o trivy-image.json ${env.IMAGE_TAG}
                    trivy image -f table -o trivy-image.txt ${env.IMAGE_TAG}
                    """
                }
            }
        }

        // NOTE: Removed 'Upload to Registry' stage because you said you are not using any registry.

        stage("Deploy to Container") {
            steps {
                script {
                    // Deploy directly from local image produced by this agent's Docker daemon
                    sh "docker rm -f vprofile || true"
                    sh "docker run -d --name vprofile -p 80:8080 ${env.IMAGE_TAG}"
                }
            }
        }

        stage("DAST Scan with OWASP ZAP") {
            steps {
                script {
                    echo '🔍 Running OWASP ZAP baseline scan...'
                    def exitCode = sh(script: '''
                        docker run --rm --user root --network host -v $(pwd):/zap/wrk:rw \
                        -t zaproxy/zap-stable zap-baseline.py \
                        -t http://localhost \
                        -r zap_report.html -J zap_report.json
                    ''', returnStatus: true)
                    echo "ZAP scan finished with exit code: ${exitCode}"
                    if (fileExists('zap_report.json')) {
                        def zapJson = readJSON file: 'zap_report.json'
                        def highCount = zapJson.site.collect { site -> site.alerts.findAll { it.risk == 'High' }.size() }.sum()
                        def mediumCount = zapJson.site.collect { site -> site.alerts.findAll { it.risk == 'Medium' }.size() }.sum()
                        def lowCount = zapJson.site.collect { site -> site.alerts.findAll { it.risk == 'Low' }.size() }.sum()
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
    } // stages

    post {
        always {
            script {
                def buildStatus = currentBuild.currentResult
                def buildUser = currentBuild.getBuildCauses('hudson.model.Cause$UserIdCause')[0]?.userId ?: 'GitHub User'
                def buildUrl = "${env.BUILD_URL}"

                slackSend(
                    channel: '#devsecopscicd',
                    color: COLOR_MAP[buildStatus],
                    message: """*${buildStatus}:* Job *${env.JOB_NAME}* Build #${env.BUILD_NUMBER}
👤 *Started by:* ${buildUser}
🔗 *Build URL:* <${buildUrl}|Click Here for Details>"""
                )

                emailext (
                    subject: "Pipeline ${buildStatus}: ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                    body: """
                        
                        <p>Maven App-tier DevSecops CICD pipeline status.</p>
                        <p>Project: ${env.JOB_NAME}</p>
                        <p>Build Number: ${env.BUILD_NUMBER}</p>
                        <p>Build Status: ${buildStatus}</p>
                        <p>Started by: ${buildUser}</p>
                        <p>Build URL: <a href="${env.BUILD_URL}">${env.BUILD_URL}</a></p>
                    """,
                    to: 'mekni.amin75@gmail.com',
                    from: 'mmekni66@gmail.com',
                    mimeType: 'text/html',
                    attachmentsPattern: 'trivyfs.txt,trivy-image.json,trivy-image.txt,dependency-check-report.xml,zap_report.html,zap_report.json'
                )
            }
        }
    }
}
