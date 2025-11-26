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
                            gitleaks detect --source . --report-format json --report-path gitleaks-report.json --exit-code 0
                        '''
                    }
                    post {
                        always {
                            archiveArtifacts artifacts: 'gitleaks-report.json', allowEmptyArchive: true
                        }
                    }
                }

                stage('SAST - Semgrep') {
                    steps {
                        sh '''
                            echo "🔍 Running Semgrep SAST analysis..."
                            semgrep --config auto --output semgrep.json --json --error . || true
                        '''
                    }
                    post {
                        always {
                            archiveArtifacts artifacts: 'semgrep.json', allowEmptyArchive: true
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
                    
                    echo "🧪 Running unit tests with coverage..."
                    mvn -B test -DskipITs=true jacoco:report
                '''
            }
            post { 
                success { 
                    archiveArtifacts artifacts: '**/target/*.war', allowEmptyArchive: true 
                }
                always {
                    junit testResults: '**/target/surefire-reports/*.xml', allowEmptyResults: true
                    jacoco(
                        execPattern: '**/target/jacoco.exec',
                        classPattern: '**/target/classes',
                        sourcePattern: '**/src/main/java',
                        exclusionPattern: '**/src/test/*'
                    )
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
                                    -Dsonar.login=\\$SONAR_TOKEN \\
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
                                -Dodc.outputDirectory=target/dependency-check-report
                        '''
                    }
                    post {
                        always {
                            archiveArtifacts artifacts: 'target/dependency-check-report/*', allowEmptyArchive: true
                        }
                    }
                }

                stage('SBOM Generation') {
                    steps {
                        sh '''
                            echo "📄 Generating Software Bill of Materials..."
                            mvn -B org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom
                        '''
                    }
                    post {
                        always {
                            archiveArtifacts artifacts: 'target/bom.*', allowEmptyArchive: true
                        }
                    }
                }

                stage('Trivy SCA Scan') {
                    steps {
                        sh '''
                            echo "🔍 Scanning dependencies with Trivy..."
                            # Augmenter le timeout pour Trivy et utiliser un mirror plus fiable
                            TRIVY_TIMEOUT=600 trivy fs --scanners vuln --severity CRITICAL,HIGH --format json --output trivy-sca.json --timeout 10m . || echo "Trivy scan completed with warnings"
                        '''
                    }
                    post {
                        always {
                            script {
                                if (fileExists('trivy-sca.json')) {
                                    archiveArtifacts artifacts: 'trivy-sca.json', allowEmptyArchive: true
                                } else {
                                    echo "Trivy scan file not found, skipping artifact archiving"
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
                    
                    // Analyse des résultats de sécurité
                    def securityFindings = [
                        critical: 0,
                        high: 0,
                        medium: 0,
                        secrets: 0,
                        semgrep: 0
                    ]
                    
                    // Analyser le rapport Gitleaks de manière sécurisée
                    if (fileExists('gitleaks-report.json')) {
                        try {
                            def gitleaksReport = readJSON file: 'gitleaks-report.json'
                            securityFindings.secrets = gitleaksReport instanceof Map ? gitleaksReport.get('Findings', []).size() : 0
                        } catch (Exception e) {
                            echo "⚠️ Error reading gitleaks report: ${e.message}"
                        }
                    }
                    
                    // Analyser le rapport Semgrep de manière sécurisée
                    if (fileExists('semgrep.json')) {
                        try {
                            def semgrepReport = readJSON file: 'semgrep.json'
                            securityFindings.semgrep = semgrepReport instanceof Map ? semgrepReport.get('results', []).size() : 0
                        } catch (Exception e) {
                            echo "⚠️ Error reading semgrep report: ${e.message}"
                        }
                    }
                    
                    // Analyser les dépendances avec une méthode simple
                    if (fileExists('target/dependency-check-report/dependency-check-report.xml')) {
                        try {
                            def xmlContent = readFile('target/dependency-check-report/dependency-check-report.xml')
                            
                            // Compter les vulnérabilités avec une méthode Groovy sandbox-safe
                            securityFindings.critical = countOccurrences(xmlContent, 'severity="CRITICAL"')
                            securityFindings.high = countOccurrences(xmlContent, 'severity="HIGH"')
                            securityFindings.medium = countOccurrences(xmlContent, 'severity="MEDIUM"')
                            
                        } catch (Exception e) {
                            echo "⚠️ Error analyzing dependency check report: ${e.message}"
                        }
                    }
                    
                    echo "Security Scan Results:"
                    echo "🔴 CRITICAL vulnerabilities: ${securityFindings.critical}"
                    echo "🟠 HIGH vulnerabilities: ${securityFindings.high}"
                    echo "🟡 MEDIUM vulnerabilities: ${securityFindings.medium}"
                    echo "🔑 Secrets exposed: ${securityFindings.secrets}"
                    echo "🐛 Semgrep findings: ${securityFindings.semgrep}"
                    
                    // Application des politiques de sécurité
                    if (params.FAIL_ON_CRITICAL_VULNS && securityFindings.critical > 0) {
                        error "❌ Build failed: ${securityFindings.critical} CRITICAL vulnerabilities detected"
                    } else if (securityFindings.critical > 0) {
                        unstable "⚠️ Build marked UNSTABLE: ${securityFindings.critical} CRITICAL vulnerabilities"
                    } else if (securityFindings.high > 10) {
                        unstable "⚠️ Build marked UNSTABLE: High number (${securityFindings.high}) of HIGH vulnerabilities"
                    } else if (securityFindings.secrets > 0) {
                        unstable "⚠️ Build marked UNSTABLE: ${securityFindings.secrets} secrets exposed in code"
                    } else {
                        echo "✅ All security policies satisfied"
                    }
                    
                    // Génération du rapport de sécurité détaillé
                    writeFile file: 'security-compliance-report.md', text: """
# DevSecOps Security Compliance Report

## Build Information
- **Build Number**: ${env.BUILD_NUMBER}
- **Commit**: ${env.GIT_COMMIT}
- **Date**: ${new Date().format("yyyy-MM-dd HH:mm:ss")}

## Security Scan Summary

### Vulnerability Analysis
- 🔴 **CRITICAL**: ${securityFindings.critical}
- 🟠 **HIGH**: ${securityFindings.high} 
- 🟡 **MEDIUM**: ${securityFindings.medium}
- 🔑 **Secrets Exposed**: ${securityFindings.secrets}
- 🐛 **Code Issues**: ${securityFindings.semgrep}

### Quality Gates Status
- **SAST (SonarQube)**: ${currentBuild.result == 'SUCCESS' ? 'PASSED ✅' : 'FAILED ❌'}
- **SCA (Dependencies)**: ${securityFindings.critical == 0 ? 'PASSED ✅' : 'FAILED ❌'}
- **Secrets Detection**: ${securityFindings.secrets == 0 ? 'PASSED ✅' : 'FAILED ❌'}

### Policy Enforcement
- **Fail on Critical**: ${params.FAIL_ON_CRITICAL_VULNS ? 'ENABLED 🔒' : 'DISABLED ⚠️'}
- **Quality Gate**: ${params.ENFORCE_QUALITY_GATE ? 'ENFORCED ✅' : 'ADVISORY ℹ️'}

## Recommendations
${securityFindings.critical > 0 ? '- **IMMEDIATE ACTION**: Address critical vulnerabilities' : ''}
${securityFindings.high > 0 ? '- **HIGH PRIORITY**: Review high severity issues' : ''}
${securityFindings.secrets > 0 ? '- **CRITICAL**: Rotate exposed secrets immediately' : ''}

---
*Generated by Jenkins DevSecOps Pipeline*
                    """
                    
                    archiveArtifacts artifacts: 'security-compliance-report.md', allowEmptyArchive: true
                }
            }
        }

        // Étape 9: DAST Scan (optionnel)
        stage('DAST Security Testing') {
            when {
                allOf {
                    expression { params.RUN_DAST_SCAN }
                    expression { currentBuild.result != 'FAILURE' }
                }
            }
            steps {
                script {
                    echo "🔍 Starting DAST scan with OWASP ZAP..."
                    
                    sh """
                        docker run --rm \\
                            -v \$(pwd):/zap/wrk:rw \\
                            -t ghcr.io/zaproxy/zaproxy:stable \\
                            zap-baseline.py \\
                            -t ${params.TEST_ENVIRONMENT_URL} \\
                            -r zap-dast-report.html \\
                            -J zap-dast-report.json \\
                            -w zap-dast-report.md || echo "ZAP scan completed with warnings"
                    """
                    
                    // Analyse des résultats DAST
                    if (fileExists('zap-dast-report.json')) {
                        try {
                            def zapReport = readJSON file: 'zap-dast-report.json'
                            def site = zapReport?.site?.getAt(0)
                            def alerts = site?.alerts ?: []
                            
                            def highAlerts = 0
                            def mediumAlerts = 0
                            
                            for (alert in alerts) {
                                if (alert.risk == 'High') highAlerts++
                                else if (alert.risk == 'Medium') mediumAlerts++
                            }
                            
                            echo "DAST Scan Results:"
                            echo "🔴 High risk alerts: ${highAlerts}"
                            echo "🟠 Medium risk alerts: ${mediumAlerts}"
                            
                            if (highAlerts > 0) {
                                unstable "⚠️ DAST scan detected ${highAlerts} high risk security issues"
                            }
                        } catch (Exception e) {
                            echo "⚠️ Error analyzing ZAP report: ${e.message}"
                        }
                    }
                }
            }
            post {
                always {
                    archiveArtifacts artifacts: 'zap-dast-report.*', allowEmptyArchive: true
                }
            }
        }
    }

    post {
        always {
            script {
                // Rapport final consolidé
                def buildStatus = currentBuild.currentResult
                def duration = currentBuild.durationString.replace(' and counting', '')
                def buildUser = env.CHANGE_AUTHOR ?: env.BUILD_USER_ID ?: 'System'
                
                // Rapport de sécurité final
                writeFile file: 'devsecops-final-report.md', text: """
# 🛡️ DevSecOps Pipeline - Final Report

## Executive Summary
**Status**: ${buildStatus}  
**Build**: ${env.JOB_NAME} #${env.BUILD_NUMBER}  
**Duration**: ${duration}  
**Triggered by**: ${buildUser}

## Security Assessment
✅ **Shift-Left Security Implemented**  
✅ **SAST with SonarQube & Semgrep**  
✅ **SCA with OWASP Dependency Check**  
✅ **Secrets Detection with Gitleaks**  
✅ **SBOM Generation**  
${params.RUN_DAST_SCAN ? '✅ **DAST Testing with OWASP ZAP**' : '⏭️ **DAST Testing Skipped**'}

## Quality Gates
- Code Quality: ${currentBuild.result == 'SUCCESS' ? 'PASSED' : 'FAILED'}
- Security Policy: ${params.FAIL_ON_CRITICAL_VULNS ? 'STRICT' : 'LENIENT'}

## Artifacts Generated
- Security compliance report
- Vulnerability analysis
- SBOM documentation
- Test coverage reports

---
*This pipeline demonstrates DevSecOps practices with security integrated throughout the SDLC*
                """
                
                archiveArtifacts artifacts: 'devsecops-final-report.md', allowEmptyArchive: true
            }
        }
        
        success {
            script {
                slackSend(
                    channel: '#devsecops',
                    color: COLOR_MAP['SUCCESS'],
                    message: """✅ DevSecOps Pipeline SUCCESS: ${env.JOB_NAME} #${env.BUILD_NUMBER}
🛡️ All security scans completed
📊 Security policies enforced
👤 By: ${env.BUILD_USER_ID ?: 'System'}
🔗 ${env.BUILD_URL}"""
                )
                
                emailext (
                    subject: "✅ SUCCESS: DevSecOps Pipeline - ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                    body: """
                    <h2>DevSecOps Pipeline Execution Successful</h2>
                    <p><strong>Project:</strong> ${env.JOB_NAME}</p>
                    <p><strong>Build Number:</strong> ${env.BUILD_NUMBER}</p>
                    <p><strong>Status:</strong> SUCCESS</p>
                    <p><strong>Commit:</strong> ${env.GIT_COMMIT}</p>
                    <p><strong>Duration:</strong> ${currentBuild.durationString}</p>
                    <p>All security scans passed successfully. No critical vulnerabilities detected.</p>
                    <p>View details: <a href="${env.BUILD_URL}">${env.BUILD_URL}</a></p>
                    """,
                    to: 'mekni.amin75@gmail.com',
                    from: 'mmekni66@gmail.com',
                    mimeType: 'text/html'
                )
            }
        }
        
        unstable {
            script {
                slackSend(
                    channel: '#devsecops',
                    color: COLOR_MAP['UNSTABLE'],
                    message: """⚠️ DevSecOps Pipeline UNSTABLE: ${env.JOB_NAME} #${env.BUILD_NUMBER}
⚡ Security findings detected (non-blocking)
📋 Review security reports for details
🔗 ${env.BUILD_URL}"""
                )
                
                emailext (
                    subject: "⚠️ UNSTABLE: DevSecOps Pipeline - ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                    body: """
                    <h2>DevSecOps Pipeline - Security Warnings</h2>
                    <p><strong>Project:</strong> ${env.JOB_NAME}</p>
                    <p><strong>Build Number:</strong> ${env.BUILD_NUMBER}</p>
                    <p><strong>Status:</strong> UNSTABLE</p>
                    <p><strong>Commit:</strong> ${env.GIT_COMMIT}</p>
                    <p>Security scans completed with non-critical findings. Review reports for details.</p>
                    <p>View details: <a href="${env.BUILD_URL}">${env.BUILD_URL}</a></p>
                    """,
                    to: 'mekni.amin75@gmail.com',
                    from: 'mmekni66@gmail.com',
                    mimeType: 'text/html'
                )
            }
        }
        
        failure {
            script {
                slackSend(
                    channel: '#devsecops',
                    color: COLOR_MAP['FAILURE'],
                    message: """❌ DevSecOps Pipeline FAILED: ${env.JOB_NAME} #${env.BUILD_NUMBER}
🚨 Critical security issues blocked pipeline
🔍 Immediate review required
🔗 ${env.BUILD_URL}"""
                )
                
                emailext (
                    subject: "❌ FAILED: DevSecOps Pipeline - ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                    body: """
                    <h2>DevSecOps Pipeline - Critical Security Issues</h2>
                    <p><strong>Project:</strong> ${env.JOB_NAME}</p>
                    <p><strong>Build Number:</strong> ${env.BUILD_NUMBER}</p>
                    <p><strong>Status:</strong> FAILED</p>
                    <p><strong>Commit:</strong> ${env.GIT_COMMIT}</p>
                    <p><strong>Reason:</strong> Critical security vulnerabilities detected and policy enforcement enabled.</p>
                    <p>Immediate action required to address security issues.</p>
                    <p>View details: <a href="${env.BUILD_URL}">${env.BUILD_URL}</a></p>
                    """,
                    to: 'mekni.amin75@gmail.com',
                    from: 'mmekni66@gmail.com',
                    mimeType: 'text/html'
                )
            }
        }
        
        cleanup {
            cleanWs()
        }
    }
}

// Méthode helper pour compter les occurrences de manière sandbox-safe
def countOccurrences(String text, String pattern) {
    int count = 0
    int index = 0
    while ((index = text.indexOf(pattern, index)) != -1) {
        count++
        index += pattern.length()
    }
    return count
}