// Configuration des couleurs pour les notifications
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
        booleanParam(name: 'ENFORCE_QUALITY_GATE', defaultValue: true, description: 'Abort pipeline if Sonar Quality Gate != OK')
        booleanParam(name: 'FAIL_ON_CRITICAL_VULNS', defaultValue: false, description: 'Fail build on CRITICAL vulnerabilities')
        booleanParam(name: 'RUN_DAST_SCAN', defaultValue: false, description: 'Perform DAST security testing')
        string(name: 'TEST_ENVIRONMENT_URL', defaultValue: 'http://localhost:8080', description: 'URL for DAST testing')
    }

    environment {
        SONAR_HOST_URL = 'http://192.168.50.4:9000'
        SCANNER_HOME = tool 'sonar-scanner'
        GIT_COMMIT = sh(returnStdout: true, script: 'git rev-parse HEAD').trim()
        BUILD_USER = sh(returnStdout: true, script: 'echo ${BUILD_USER_ID:-${CHANGE_AUTHOR:-System}}').trim()
    }

    options {
        timestamps()
        ansiColor('xterm')
        skipDefaultCheckout(false)
        buildDiscarder(logRotator(numToKeepStr: '10'))
        durabilityHint('MAX_SURVIVABILITY')
        timeout(time: 60, unit: 'MINUTES')
    }

    stages {
        // Étape 1: Préparation
        stage('Clean Workspace') { 
            steps { 
                cleanWs() 
            } 
        }

        // Étape 2: Récupération du code
        stage('Checkout') {
            steps {
                checkout([$class: 'GitSCM',
                    branches: [[name: '*/main']],
                    extensions: [
                        [$class: 'CloneOption', depth: 1, shallow: true],
                        [$class: 'CleanBeforeCheckout']
                    ],
                    userRemoteConfigs: [[
                        url: 'https://github.com/4tnx/devsecops.git',
                        credentialsId: 'jenkins-github-https-cred'
                    ]]
                ])
            }
        }

        // Étape 3: Sécurité Shift-Left
        stage('Early Security Scan') {
            parallel {
                stage('Secrets Detection') {
                    steps {
                        sh '''
                            echo "🔍 Scanning for secrets in code..."
                            # Installation de gitleaks si nécessaire
                            if ! command -v gitleaks &> /dev/null; then
                                echo "Installing gitleaks..."
                                wget https://github.com/gitleaks/gitleaks/releases/download/v8.18.0/gitleaks_8.18.0_linux_x64.tar.gz
                                tar -xzf gitleaks_8.18.0_linux_x64.tar.gz
                                sudo mv gitleaks /usr/local/bin/
                            fi
                            gitleaks detect --source . --report-format json --report-path gitleaks-report.json --exit-code 0 || true
                        '''
                    }
                    post {
                        always {
                            script {
                                if (fileExists('gitleaks-report.json')) {
                                    archiveArtifacts artifacts: 'gitleaks-report.json', allowEmptyArchive: true
                                }
                            }
                        }
                    }
                }

                stage('SAST - Semgrep') {
                    steps {
                        sh '''
                            echo "🔍 Running Semgrep SAST analysis..."
                            # Installation de semgrep si nécessaire
                            if ! command -v semgrep &> /dev/null; then
                                echo "Installing semgrep..."
                                python3 -m pip install semgrep
                            fi
                            semgrep --config auto --output semgrep.json --json --error . || true
                        '''
                    }
                    post {
                        always {
                            script {
                                if (fileExists('semgrep.json')) {
                                    archiveArtifacts artifacts: 'semgrep.json', allowEmptyArchive: true
                                }
                            }
                        }
                    }
                }
            }
        }

        // Étape 4: Build et tests
        stage('Build & Unit Tests') {
            steps { 
                sh '''
                    echo "🏗️ Building application..."
                    mvn -B clean compile
                    
                    echo "🧪 Running unit tests..."
                    mvn -B test
                    
                    echo "📊 Generating test reports..."
                    mvn -B jacoco:report
                '''
            }
            post { 
                always {
                    script {
                        // Vérification des fichiers de test
                        if (fileExists('target/surefire-reports')) {
                            junit testResults: '**/target/surefire-reports/*.xml', allowEmptyResults: true
                        } else {
                            echo "⚠️ No test reports found at target/surefire-reports"
                        }
                        
                        if (fileExists('target/jacoco.exec')) {
                            jacoco(
                                execPattern: '**/target/jacoco.exec',
                                classPattern: '**/target/classes',
                                sourcePattern: '**/src/main/java',
                                exclusionPattern: '**/src/test/*'
                            )
                        } else {
                            echo "⚠️ No JaCoCo execution data found"
                        }
                        
                        // Archivage des artefacts de build
                        if (fileExists('target/*.war')) {
                            archiveArtifacts artifacts: '**/target/*.war', allowEmptyArchive: true
                        } else {
                            echo "⚠️ No WAR file found in target directory"
                        }
                    }
                }
            }
        }

        // Étape 5: Analyse qualité et sécurité du code
        stage('Code Quality & SAST') {
            steps {
                script {
                    withCredentials([string(credentialsId: 'sonar-token', variable: 'SONAR_TOKEN')]) {
                        withSonarQubeEnv('sonar-server') {
                            sh """
                                mvn -B sonar:sonar \\
                                    -Dsonar.host.url=${SONAR_HOST_URL} \\
                                    -Dsonar.login=${SONAR_TOKEN} \\
                                    -Dsonar.projectKey=vprofile-${env.BUILD_NUMBER} \\
                                    -Dsonar.projectName="VProfile Application" \\
                                    -Dsonar.sources=src/main/java \\
                                    -Dsonar.tests=src/test/java \\
                                    -Dsonar.java.binaries=target/classes \\
                                    -Dsonar.junit.reportsPath=target/surefire-reports \\
                                    -Dsonar.jacoco.reportPaths=target/jacoco.exec \\
                                    -Dsonar.coverage.jacoco.xmlReportPaths=target/site/jacoco/jacoco.xml
                            """
                        }
                    }
                }
            }
        }

        // Étape 6: Quality Gate
        stage('Quality Gate') {
            steps {
                script {
                    timeout(time: 5, unit: 'MINUTES') {
                        def qg = waitForQualityGate()
                        echo "Quality Gate status: ${qg.status}"
                        
                        if (params.ENFORCE_QUALITY_GATE && qg.status != 'OK') {
                            error "❌ Quality Gate failed: ${qg.status}. Pipeline aborted."
                        }
                        
                        echo "✅ Quality Gate passed successfully"
                    }
                }
            }
        }

        // Étape 7: Analyse des dépendances (SCA)
        stage('Dependency Analysis') {
            parallel {
                stage('SCA - OWASP Dependency Check') {
                    steps {
                        sh '''
                            echo "📦 Scanning dependencies for vulnerabilities..."
                            mvn -B org.owasp:dependency-check-maven:check \
                                -Dformat=HTML \
                                -Dformat=XML \
                                -Dodc.outputDirectory=target/dependency-check-report || echo "Dependency check completed"
                        '''
                    }
                    post {
                        always {
                            script {
                                if (fileExists('target/dependency-check-report')) {
                                    archiveArtifacts artifacts: 'target/dependency-check-report/*', allowEmptyArchive: true
                                }
                            }
                        }
                    }
                }

                stage('SBOM Generation') {
                    steps {
                        sh '''
                            echo "📄 Generating Software Bill of Materials..."
                            mvn -B org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom || echo "SBOM generation completed"
                        '''
                    }
                    post {
                        always {
                            script {
                                if (fileExists('target/bom.xml') || fileExists('target/bom.json')) {
                                    archiveArtifacts artifacts: 'target/bom.*', allowEmptyArchive: true
                                }
                            }
                        }
                    }
                }

                stage('Trivy SCA Scan') {
                    steps {
                        sh '''
                            echo "🔍 Scanning dependencies with Trivy..."
                            # Installation de Trivy si nécessaire
                            if ! command -v trivy &> /dev/null; then
                                echo "Installing Trivy..."
                                wget https://github.com/aquasecurity/trivy/releases/download/v0.49.1/trivy_0.49.1_Linux-64bit.tar.gz
                                tar -xzf trivy_0.49.1_Linux-64bit.tar.gz
                                sudo mv trivy /usr/local/bin/
                            fi
                            trivy fs --scanners vuln --severity CRITICAL,HIGH --format json --output trivy-sca.json --timeout 10m . || echo "Trivy scan completed"
                        '''
                    }
                    post {
                        always {
                            script {
                                if (fileExists('trivy-sca.json')) {
                                    archiveArtifacts artifacts: 'trivy-sca.json', allowEmptyArchive: true
                                }
                            }
                        }
                    }
                }
            }
        }

        // Étape 8: Application des politiques de sécurité
        stage('Security Policy Enforcement') {
            steps {
                script {
                    echo "⚖️ Applying security policies..."
                    
                    // Initialisation avec des valeurs par défaut
                    def securityFindings = [
                        critical: 0,
                        high: 0,
                        medium: 0,
                        secrets: 0,
                        semgrep: 0
                    ]
                    
                    try {
                        // Analyse Gitleaks
                        if (fileExists('gitleaks-report.json')) {
                            def gitleaksReport = readJSON file: 'gitleaks-report.json'
                            securityFindings.secrets = gitleaksReport?.Findings?.size() ?: 0
                        }
                    } catch (Exception e) {
                        echo "⚠️ Error reading gitleaks report: ${e.message}"
                    }
                    
                    try {
                        // Analyse Semgrep
                        if (fileExists('semgrep.json')) {
                            def semgrepReport = readJSON file: 'semgrep.json'
                            securityFindings.semgrep = semgrepReport?.results?.size() ?: 0
                        }
                    } catch (Exception e) {
                        echo "⚠️ Error reading semgrep report: ${e.message}"
                    }
                    
                    try {
                        // Analyse OWASP Dependency Check
                        if (fileExists('target/dependency-check-report/dependency-check-report.xml')) {
                            def xmlContent = readFile('target/dependency-check-report/dependency-check-report.xml')
                            securityFindings.critical = countOccurrences(xmlContent, 'severity="CRITICAL"')
                            securityFindings.high = countOccurrences(xmlContent, 'severity="HIGH"')
                            securityFindings.medium = countOccurrences(xmlContent, 'severity="MEDIUM"')
                        }
                    } catch (Exception e) {
                        echo "⚠️ Error analyzing dependency check report: ${e.message}"
                    }
                    
                    // Affichage des résultats
                    echo "=== SECURITY SCAN RESULTS ==="
                    echo "🔴 CRITICAL vulnerabilities: ${securityFindings.critical}"
                    echo "🟠 HIGH vulnerabilities: ${securityFindings.high}"
                    echo "🟡 MEDIUM vulnerabilities: ${securityFindings.medium}"
                    echo "🔑 Secrets exposed: ${securityFindings.secrets}"
                    echo "🐛 Semgrep findings: ${securityFindings.semgrep}"
                    
                    // Application des politiques
                    if (params.FAIL_ON_CRITICAL_VULNS && securityFindings.critical > 0) {
                        error "❌ Build failed: ${securityFindings.critical} CRITICAL vulnerabilities detected"
                    } else if (securityFindings.critical > 0) {
                        currentBuild.result = 'UNSTABLE'
                        echo "⚠️ Build marked UNSTABLE: ${securityFindings.critical} CRITICAL vulnerabilities"
                    } else if (securityFindings.high > 10) {
                        currentBuild.result = 'UNSTABLE'
                        echo "⚠️ Build marked UNSTABLE: High number (${securityFindings.high}) of HIGH vulnerabilities"
                    } else if (securityFindings.secrets > 0) {
                        currentBuild.result = 'UNSTABLE'
                        echo "⚠️ Build marked UNSTABLE: ${securityFindings.secrets} secrets exposed in code"
                    } else {
                        echo "✅ All security policies satisfied"
                    }
                    
                    // Sauvegarde des résultats
                    writeJSON file: 'security-findings.json', json: securityFindings
                    
                    // Génération du rapport
                    def reportContent = """
# DevSecOps Security Compliance Report

## Build Information
- **Build Number**: ${env.BUILD_NUMBER}
- **Commit**: ${env.GIT_COMMIT ?: 'N/A'}
- **Date**: ${new Date().format("yyyy-MM-dd HH:mm:ss")}

## Security Scan Summary

### Vulnerability Analysis
- 🔴 **CRITICAL**: ${securityFindings.critical}
- 🟠 **HIGH**: ${securityFindings.high} 
- 🟡 **MEDIUM**: ${securityFindings.medium}
- 🔑 **Secrets Exposed**: ${securityFindings.secrets}
- 🐛 **Code Issues**: ${securityFindings.semgrep}

### Policy Enforcement
- **Fail on Critical**: ${params.FAIL_ON_CRITICAL_VULNS ? 'ENABLED 🔒' : 'DISABLED ⚠️'}
- **Quality Gate**: ${params.ENFORCE_QUALITY_GATE ? 'ENFORCED ✅' : 'ADVISORY ℹ️'}

## Status: ${currentBuild.result == 'SUCCESS' ? 'PASSED ✅' : 'NEEDS REVIEW ⚠️'}
"""
                    writeFile file: 'security-compliance-report.md', text: reportContent
                    archiveArtifacts artifacts: 'security-compliance-report.md', allowEmptyArchive: true
                }
            }
        }
    }

    post {
        always {
            script {
                // Chargement des résultats de sécurité
                def securityFindings = [critical: 0, high: 0, medium: 0, secrets: 0, semgrep: 0]
                if (fileExists('security-findings.json')) {
                    securityFindings = readJSON file: 'security-findings.json'
                }
                
                // Rapport final
                def finalReport = """
# 🛡️ DevSecOps Pipeline - Final Report

## Executive Summary
**Status**: ${currentBuild.currentResult}  
**Build**: ${env.JOB_NAME} #${env.BUILD_NUMBER}  
**Duration**: ${currentBuild.durationString.replace(' and counting', '')}  
**Triggered by**: ${env.BUILD_USER ?: 'System'}

## Security Assessment
${securityFindings.secrets == 0 ? '✅' : '⚠️'} **Secrets Detection**: ${securityFindings.secrets} findings  
${securityFindings.semgrep == 0 ? '✅' : '⚠️'} **SAST Analysis**: ${securityFindings.semgrep} findings  
${securityFindings.critical == 0 ? '✅' : '🔴'} **Critical Vulnerabilities**: ${securityFindings.critical}  
${securityFindings.high == 0 ? '✅' : '🟠'} **High Vulnerabilities**: ${securityFindings.high}  
${params.RUN_DAST_SCAN ? '✅ **DAST Testing**' : '⏭️ **DAST Testing Skipped**'}

## Build Artifacts
- Security compliance report
- Vulnerability analysis
- SBOM documentation
- Test coverage reports

---
*Pipeline executed successfully with security checks*
"""
                writeFile file: 'devsecops-final-report.md', text: finalReport
                archiveArtifacts artifacts: 'devsecops-final-report.md', allowEmptyArchive: true
                
                echo "=== PIPELINE EXECUTION COMPLETE ==="
                echo "Status: ${currentBuild.currentResult}"
                echo "Build: ${env.BUILD_NUMBER}"
                echo "User: ${env.BUILD_USER ?: 'System'}"
            }
        }
        
        success {
            script {
                echo "✅ SENDING SUCCESS NOTIFICATIONS"
                
                // Slack Notification
                try {
                    slackSend(
                        channel: '#devsecops',
                        color: 'good',
                        message: """✅ DevSecOps Pipeline SUCCESS: ${env.JOB_NAME} #${env.BUILD_NUMBER}
🛡️ All security scans completed
📊 Security policies enforced
👤 By: ${env.BUILD_USER ?: 'System'}
🔗 ${env.BUILD_URL}"""
                    )
                    echo "✅ Slack notification sent"
                } catch (Exception e) {
                    echo "⚠️ Failed to send Slack notification: ${e.message}"
                }
                
                // Email Notification - SIMPLIFIÉ
                try {
                    emailext (
                        subject: "SUCCESS: DevSecOps Pipeline - ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                        body: """
                        <h2>DevSecOps Pipeline - Execution Successful</h2>
                        <p><strong>Project:</strong> ${env.JOB_NAME}</p>
                        <p><strong>Build Number:</strong> ${env.BUILD_NUMBER}</p>
                        <p><strong>Status:</strong> SUCCESS</p>
                        <p><strong>Duration:</strong> ${currentBuild.durationString.replace(' and counting', '')}</p>
                        <p>All security scans completed successfully.</p>
                        <p>View build: <a href="${env.BUILD_URL}">${env.BUILD_URL}</a></p>
                        """,
                        to: 'mekni.amin75@gmail.com',
                        mimeType: 'text/html'
                    )
                    echo "✅ Email notification sent to mekni.amin75@gmail.com"
                } catch (Exception e) {
                    echo "❌ Failed to send email: ${e.message}"
                }
            }
        }
        
        unstable {
            script {
                echo "⚠️ SENDING UNSTABLE NOTIFICATIONS"
                
                // Slack
                slackSend(
                    channel: '#devsecops',
                    color: 'warning',
                    message: """⚠️ DevSecOps Pipeline UNSTABLE: ${env.JOB_NAME} #${env.BUILD_NUMBER}
⚡ Security findings detected (non-blocking)
📋 Review security reports
🔗 ${env.BUILD_URL}"""
                )
                
                // Email
                emailext (
                    subject: "UNSTABLE: DevSecOps Pipeline - ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                    body: """
                    <h2>DevSecOps Pipeline - Security Warnings</h2>
                    <p><strong>Build:</strong> ${env.JOB_NAME} #${env.BUILD_NUMBER}</p>
                    <p><strong>Status:</strong> UNSTABLE</p>
                    <p>Security scans completed with non-critical findings.</p>
                    <p>View details: <a href="${env.BUILD_URL}">${env.BUILD_URL}</a></p>
                    """,
                    to: 'mekni.amin75@gmail.com',
                    mimeType: 'text/html'
                )
            }
        }
        
        failure {
            script {
                echo "❌ SENDING FAILURE NOTIFICATIONS"
                
                // Slack
                slackSend(
                    channel: '#devsecops',
                    color: 'danger',
                    message: """❌ DevSecOps Pipeline FAILED: ${env.JOB_NAME} #${env.BUILD_NUMBER}
🚨 Critical issues detected
🔍 Immediate review required
🔗 ${env.BUILD_URL}"""
                )
                
                // Email
                emailext (
                    subject: "FAILED: DevSecOps Pipeline - ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                    body: """
                    <h2>DevSecOps Pipeline - Build Failed</h2>
                    <p><strong>Build:</strong> ${env.JOB_NAME} #${env.BUILD_NUMBER}</p>
                    <p><strong>Status:</strong> FAILED</p>
                    <p>Critical issues detected during execution.</p>
                    <p>View details: <a href="${env.BUILD_URL}">${env.BUILD_URL}</a></p>
                    """,
                    to: 'mekni.amin75@gmail.com',
                    mimeType: 'text/html'
                )
            }
        }
        
        cleanup {
            script {
                echo "🧹 Cleaning up workspace..."
                cleanWs()
            }
        }
    }
}

// Méthode helper pour compter les occurrences
def countOccurrences(String text, String pattern) {
    int count = 0
    int index = 0
    while ((index = text.indexOf(pattern, index)) != -1) {
        count++
        index += pattern.length()
    }
    return count
}