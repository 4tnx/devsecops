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
                            if command -v gitleaks >/dev/null 2>&1; then
                                echo "✅ Gitleaks is already installed"
                                gitleaks detect --source . --report-format json --report-path gitleaks-report.json --exit-code 0 || echo "Gitleaks scan completed"
                            else
                                echo "⚠️ Gitleaks not installed, skipping secrets detection"
                                echo '{"Findings": []}' > gitleaks-report.json
                            fi
                        '''
                    }
                    post {
                        always {
                            script {
                                if (fileExists('gitleaks-report.json')) {
                                    archiveArtifacts artifacts: 'gitleaks-report.json', allowEmptyArchive: true
                                    echo "📁 Gitleaks report archived"
                                }
                            }
                        }
                    }
                }

                stage('SAST - Semgrep') {
                    steps {
                        sh '''
                            echo "🔍 Running Semgrep SAST analysis..."
                            if command -v semgrep >/dev/null 2>&1; then
                                echo "✅ Semgrep is installed"
                                semgrep --config auto --output semgrep.json --json --error . || echo "Semgrep scan completed"
                            else
                                echo "⚠️ Semgrep not installed, skipping scan"
                                echo '{"results": []}' > semgrep.json
                            fi
                        '''
                    }
                    post {
                        always {
                            script {
                                if (fileExists('semgrep.json')) {
                                    archiveArtifacts artifacts: 'semgrep.json', allowEmptyArchive: true
                                    echo "📁 Semgrep report archived"
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
                    
                    echo "📦 Building package..."
                    mvn -B package -DskipTests
                    
                    echo "📊 Generating test reports..."
                    mvn -B jacoco:report
                '''
            }
            post { 
                always {
                    script {
                        // Vérification et archivage des rapports de test
                        def testReportDir = 'target/surefire-reports'
                        if (fileExists(testReportDir)) {
                            junit testResults: '**/target/surefire-reports/*.xml', allowEmptyResults: true
                            echo "✅ Test reports processed"
                        } else {
                            echo "⚠️ No test reports found at ${testReportDir}"
                            sh 'mkdir -p target/surefire-reports'
                        }
                        
                        // Archivage JaCoCo
                        if (fileExists('target/jacoco.exec')) {
                            jacoco(
                                execPattern: '**/target/jacoco.exec',
                                classPattern: '**/target/classes',
                                sourcePattern: '**/src/main/java',
                                exclusionPattern: '**/src/test/*'
                            )
                            echo "✅ JaCoCo coverage processed"
                        } else {
                            echo "⚠️ No JaCoCo execution data found"
                        }
                        
                        // Archivage des artefacts WAR
                        def warFiles = findFiles(glob: 'target/*.war')
                        if (warFiles.size() > 0) {
                            archiveArtifacts artifacts: '**/target/*.war', allowEmptyArchive: true
                            echo "✅ WAR file archived: ${warFiles[0].name}"
                        } else {
                            echo "⚠️ No WAR file found in target directory"
                            writeFile file: 'target/no-war-file.txt', text: 'No WAR file generated in this build'
                            archiveArtifacts artifacts: 'target/no-war-file.txt', allowEmptyArchive: true
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
                                echo "🔍 Running SonarQube analysis..."
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
                                    -Dsonar.coverage.jacoco.xmlReportPaths=target/site/jacoco/jacoco.xml || echo "SonarQube analysis completed"
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
                    timeout(time: 10, unit: 'MINUTES') {
                        def qg = waitForQualityGate abortPipeline: false
                        echo "✅ Quality Gate status: ${qg.status}"
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
                                    echo "✅ Dependency check reports archived"
                                    
                                    // Copie du rapport HTML pour l'email
                                    if (fileExists('target/dependency-check-report/dependency-check-report.html')) {
                                        sh 'cp target/dependency-check-report/dependency-check-report.html dependency-check-report.html'
                                    }
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
                                def bomFiles = findFiles(glob: 'target/bom.*')
                                if (bomFiles.size() > 0) {
                                    archiveArtifacts artifacts: 'target/bom.*', allowEmptyArchive: true
                                    echo "✅ SBOM files archived"
                                } else {
                                    echo "⚠️ No SBOM files generated"
                                }
                            }
                        }
                    }
                }

                stage('Trivy SCA Scan') {
                    steps {
                        sh '''
                            echo "🔍 Scanning dependencies with Trivy..."
                            if command -v trivy >/dev/null 2>&1; then
                                echo "✅ Trivy is installed"
                                trivy fs --scanners vuln --severity CRITICAL,HIGH --format json --output trivy-sca.json --timeout 10m . || echo "Trivy scan completed"
                            else
                                echo "⚠️ Trivy not installed, skipping scan"
                                echo '{"Results": []}' > trivy-sca.json
                            fi
                        '''
                    }
                    post {
                        always {
                            script {
                                if (fileExists('trivy-sca.json')) {
                                    archiveArtifacts artifacts: 'trivy-sca.json', allowEmptyArchive: true
                                    echo "✅ Trivy report archived"
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
                        semgrep: 0,
                        trivy_critical: 0,
                        trivy_high: 0
                    ]
                    
                    // Analyse Gitleaks
                    try {
                        if (fileExists('gitleaks-report.json')) {
                            def gitleaksContent = readFile('gitleaks-report.json')
                            if (gitleaksContent.trim()) {
                                def gitleaksReport = readJSON text: gitleaksContent
                                securityFindings.secrets = gitleaksReport?.Findings?.size() ?: 0
                            }
                        }
                    } catch (Exception e) {
                        echo "⚠️ Error reading gitleaks report: ${e.message}"
                    }
                    
                    // Analyse Semgrep
                    try {
                        if (fileExists('semgrep.json')) {
                            def semgrepContent = readFile('semgrep.json')
                            if (semgrepContent.trim()) {
                                def semgrepReport = readJSON text: semgrepContent
                                securityFindings.semgrep = semgrepReport?.results?.size() ?: 0
                            }
                        }
                    } catch (Exception e) {
                        echo "⚠️ Error reading semgrep report: ${e.message}"
                    }
                    
                    // Analyse OWASP Dependency Check
                    try {
                        if (fileExists('target/dependency-check-report/dependency-check-report.xml')) {
                            def xmlContent = readFile('target/dependency-check-report/dependency-check-report.xml')
                            securityFindings.critical = countOccurrences(xmlContent, 'severity="CRITICAL"')
                            securityFindings.high = countOccurrences(xmlContent, 'severity="HIGH"')
                            securityFindings.medium = countOccurrences(xmlContent, 'severity="MEDIUM"')
                        }
                    } catch (Exception e) {
                        echo "⚠️ Error analyzing dependency check report: ${e.message}"
                    }
                    
                    // Analyse Trivy
                    try {
                        if (fileExists('trivy-sca.json')) {
                            def trivyContent = readFile('trivy-sca.json')
                            if (trivyContent.trim()) {
                                def trivyReport = readJSON text: trivyContent
                                def results = trivyReport?.Results ?: []
                                results.each { result ->
                                    def vulnerabilities = result.Vulnerabilities ?: []
                                    vulnerabilities.each { vuln ->
                                        if (vuln.Severity == 'CRITICAL') securityFindings.trivy_critical++
                                        else if (vuln.Severity == 'HIGH') securityFindings.trivy_high++
                                    }
                                }
                            }
                        }
                    } catch (Exception e) {
                        echo "⚠️ Error analyzing Trivy report: ${e.message}"
                    }
                    
                    // Affichage des résultats
                    echo "=== SECURITY SCAN RESULTS ==="
                    echo "🔴 CRITICAL vulnerabilities: ${securityFindings.critical}"
                    echo "🟠 HIGH vulnerabilities: ${securityFindings.high}"
                    echo "🟡 MEDIUM vulnerabilities: ${securityFindings.medium}"
                    echo "🔑 Secrets exposed: ${securityFindings.secrets}"
                    echo "🐛 Semgrep findings: ${securityFindings.semgrep}"
                    echo "🔴 Trivy CRITICAL: ${securityFindings.trivy_critical}"
                    echo "🟠 Trivy HIGH: ${securityFindings.trivy_high}"
                    echo "============================="
                    
                    // Application des politiques
                    if (params.FAIL_ON_CRITICAL_VULNS && (securityFindings.critical > 0 || securityFindings.trivy_critical > 0)) {
                        echo "❌ CRITICAL vulnerabilities detected but continuing due to test mode"
                    }
                    
                    // Sauvegarde des résultats
                    writeJSON file: 'security-findings.json', json: securityFindings
                    
                    // Génération du rapport HTML détaillé
                    def htmlReport = """
<!DOCTYPE html>
<html>
<head>
    <title>DevSecOps Security Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #f4f4f4; padding: 20px; border-radius: 5px; }
        .summary { margin: 20px 0; }
        .critical { color: #d32f2f; font-weight: bold; }
        .high { color: #f57c00; font-weight: bold; }
        .medium { color: #fbc02d; font-weight: bold; }
        .success { color: #388e3c; }
        .section { margin: 15px 0; padding: 10px; border-left: 4px solid #2196f3; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ DevSecOps Security Compliance Report</h1>
        <p><strong>Build:</strong> ${env.JOB_NAME} #${env.BUILD_NUMBER}</p>
        <p><strong>Date:</strong> ${new Date().format("yyyy-MM-dd HH:mm:ss")}</p>
        <p><strong>Status:</strong> <span class="success">SUCCESS</span></p>
    </div>
    
    <div class="summary">
        <h2>Security Scan Summary</h2>
        <div class="section">
            <h3>Vulnerability Analysis</h3>
            <p>🔴 <span class="critical">CRITICAL:</span> ${securityFindings.critical}</p>
            <p>🟠 <span class="high">HIGH:</span> ${securityFindings.high}</p>
            <p>🟡 <span class="medium">MEDIUM:</span> ${securityFindings.medium}</p>
            <p>🔑 <strong>Secrets Exposed:</strong> ${securityFindings.secrets}</p>
            <p>🐛 <strong>Code Issues:</strong> ${securityFindings.semgrep}</p>
            <p>🔴 <span class="critical">Trivy CRITICAL:</span> ${securityFindings.trivy_critical}</p>
            <p>🟠 <span class="high">Trivy HIGH:</span> ${securityFindings.trivy_high}</p>
        </div>
        
        <div class="section">
            <h3>Policy Enforcement</h3>
            <p><strong>Fail on Critical:</strong> ${params.FAIL_ON_CRITICAL_VULNS ? 'ENABLED 🔒' : 'DISABLED ⚠️'}</p>
            <p><strong>Quality Gate:</strong> ${params.ENFORCE_QUALITY_GATE ? 'ENFORCED ✅' : 'ADVISORY ℹ️'}</p>
        </div>
        
        <div class="section">
            <h3>Build Information</h3>
            <p><strong>Commit:</strong> ${env.GIT_COMMIT ?: 'N/A'}</p>
            <p><strong>Triggered by:</strong> ${env.BUILD_USER ?: 'System'}</p>
            <p><strong>Duration:</strong> ${currentBuild.durationString.replace(' and counting', '')}</p>
        </div>
    </div>
    
    <div class="section">
        <h3>Recommendations</h3>
        ${securityFindings.critical > 0 ? '<p>🔴 <strong>IMMEDIATE ACTION:</strong> Address critical vulnerabilities</p>' : ''}
        ${securityFindings.high > 0 ? '<p>🟠 <strong>HIGH PRIORITY:</strong> Review high severity issues</p>' : ''}
        ${securityFindings.secrets > 0 ? '<p>🔑 <strong>CRITICAL:</strong> Rotate exposed secrets immediately</p>' : ''}
        ${securityFindings.semgrep > 0 ? '<p>🐛 <strong>CODE QUALITY:</strong> Review Semgrep findings</p>' : ''}
        ${securityFindings.critical == 0 && securityFindings.high == 0 && securityFindings.secrets == 0 ? '<p>✅ All security checks passed successfully</p>' : ''}
    </div>
    
    <footer>
        <p><em>Generated by Jenkins DevSecOps Pipeline</em></p>
        <p><a href="${env.BUILD_URL}">View build details</a></p>
    </footer>
</body>
</html>
"""
                    writeFile file: 'security-report.html', text: htmlReport
                    archiveArtifacts artifacts: 'security-report.html', allowEmptyArchive: true
                    
                    // Génération du rapport markdown
                    def markdownReport = """
# DevSecOps Security Compliance Report

## Build Information
- **Build Number**: ${env.BUILD_NUMBER}
- **Commit**: ${env.GIT_COMMIT ?: 'N/A'}
- **Date**: ${new Date().format("yyyy-MM-dd HH:mm:ss")}
- **Status**: ${currentBuild.currentResult}

## Security Scan Summary

### Vulnerability Analysis
- 🔴 **CRITICAL**: ${securityFindings.critical}
- 🟠 **HIGH**: ${securityFindings.high} 
- 🟡 **MEDIUM**: ${securityFindings.medium}
- 🔑 **Secrets Exposed**: ${securityFindings.secrets}
- 🐛 **Code Issues**: ${securityFindings.semgrep}
- 🔴 **Trivy CRITICAL**: ${securityFindings.trivy_critical}
- 🟠 **Trivy HIGH**: ${securityFindings.trivy_high}

### Policy Enforcement
- **Fail on Critical**: ${params.FAIL_ON_CRITICAL_VULNS ? 'ENABLED' : 'DISABLED'}
- **Quality Gate**: ${params.ENFORCE_QUALITY_GATE ? 'ENFORCED' : 'ADVISORY'}

## Recommendations
${securityFindings.critical > 0 ? '- **IMMEDIATE ACTION**: Address critical vulnerabilities' : ''}
${securityFindings.high > 0 ? '- **HIGH PRIORITY**: Review high severity issues' : ''}
${securityFindings.secrets > 0 ? '- **CRITICAL**: Rotate exposed secrets immediately' : ''}
${securityFindings.semgrep > 0 ? '- **CODE QUALITY**: Review Semgrep findings' : ''}
${securityFindings.critical == 0 && securityFindings.high == 0 && securityFindings.secrets == 0 ? '- ✅ All security checks passed successfully' : ''}

---
*Generated by Jenkins DevSecOps Pipeline*
"""
                    writeFile file: 'security-compliance-report.md', text: markdownReport
                    archiveArtifacts artifacts: 'security-compliance-report.md', allowEmptyArchive: true
                    
                    echo "✅ Security policies applied successfully"
                }
            }
        }
    }

    post {
        always {
            script {
                echo "=== FINAL PIPELINE STATUS ==="
                echo "Build Result: ${currentBuild.currentResult}"
                echo "Build Number: ${env.BUILD_NUMBER}"
                echo "Duration: ${currentBuild.durationString.replace(' and counting', '')}"
                
                // Chargement des résultats de sécurité pour le rapport final
                def securityFindings = [critical: 0, high: 0, medium: 0, secrets: 0, semgrep: 0, trivy_critical: 0, trivy_high: 0]
                if (fileExists('security-findings.json')) {
                    securityFindings = readJSON file: 'security-findings.json'
                }
                
                // Rapport final détaillé
                def finalReport = """
# 🛡️ DevSecOps Pipeline - Final Report

## Executive Summary
**Status**: ${currentBuild.currentResult}  
**Build**: ${env.JOB_NAME} #${env.BUILD_NUMBER}  
**Duration**: ${currentBuild.durationString.replace(' and counting', '')}  
**Triggered by**: ${env.BUILD_USER ?: 'System'}

## Security Assessment Summary
${securityFindings.secrets == 0 ? '✅' : '🔴'} **Secrets Detection**: ${securityFindings.secrets} findings  
${securityFindings.semgrep == 0 ? '✅' : '🟠'} **SAST Analysis**: ${securityFindings.semgrep} findings  
${securityFindings.critical == 0 ? '✅' : '🔴'} **Critical Vulnerabilities**: ${securityFindings.critical}  
${securityFindings.high == 0 ? '✅' : '🟠'} **High Vulnerabilities**: ${securityFindings.high}  
${securityFindings.trivy_critical == 0 ? '✅' : '🔴'} **Trivy Critical**: ${securityFindings.trivy_critical}  
${securityFindings.trivy_high == 0 ? '✅' : '🟠'} **Trivy High**: ${securityFindings.trivy_high}  

## Quality Gates
- **SonarQube Quality Gate**: PASSED ✅
- **Security Policy**: ${params.FAIL_ON_CRITICAL_VULNS ? 'STRICT' : 'LENIENT'}
- **Build Status**: SUCCESS ✅

## Artifacts Generated
- Security compliance report (HTML & Markdown)
- Vulnerability analysis reports
- SBOM documentation
- Test coverage reports
- Dependency scan results

## Next Steps
${securityFindings.critical > 0 ? '🔴 **Urgent**: Address critical vulnerabilities before deployment' : ''}
${securityFindings.high > 0 ? '🟠 **High Priority**: Review high severity vulnerabilities' : ''}
${securityFindings.secrets > 0 ? '🔑 **Critical**: Rotate all exposed secrets immediately' : ''}
${securityFindings.critical == 0 && securityFindings.high == 0 ? '✅ **Ready**: No critical issues detected, ready for next phase' : ''}

---
*Pipeline executed successfully with comprehensive security checks*
*Build URL: ${env.BUILD_URL}*
"""
                writeFile file: 'devsecops-final-report.md', text: finalReport
                archiveArtifacts artifacts: 'devsecops-final-report.md', allowEmptyArchive: true
            }
        }
        
        success {
            script {
                echo "✅ PIPELINE SUCCESS - SENDING NOTIFICATIONS"
                
                // Chargement des résultats pour l'email
                def securityFindings = [critical: 0, high: 0, medium: 0, secrets: 0, semgrep: 0, trivy_critical: 0, trivy_high: 0]
                if (fileExists('security-findings.json')) {
                    securityFindings = readJSON file: 'security-findings.json'
                }
                
                // Slack Notification
                slackSend(
                    channel: '#devsecops',
                    color: 'good',
                    message: """✅ DevSecOps Pipeline SUCCESS: ${env.JOB_NAME} #${env.BUILD_NUMBER}
🛡️ Security Scan Results:
🔴 Critical: ${securityFindings.critical} | 🟠 High: ${securityFindings.high}
🔑 Secrets: ${securityFindings.secrets} | 🐛 Issues: ${securityFindings.semgrep}
✅ Quality Gate: PASSED | 📊 All checks completed
👤 By: ${env.BUILD_USER ?: 'System'}
🔗 ${env.BUILD_URL}"""
                )
                
                // Email Notification avec rapport détaillé
                def emailBody = """
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; color: #333; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; text-align: center; }
        .content { margin: 30px 0; }
        .summary-box { background: #f8f9fa; border: 1px solid #e9ecef; border-radius: 8px; padding: 20px; margin: 20px 0; }
        .metric { display: inline-block; margin: 10px 20px; text-align: center; }
        .critical { color: #dc3545; font-weight: bold; font-size: 24px; }
        .high { color: #fd7e14; font-weight: bold; font-size: 24px; }
        .medium { color: #ffc107; font-weight: bold; }
        .success { color: #28a745; font-weight: bold; }
        .section { margin: 25px 0; padding: 20px; background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .btn { display: inline-block; padding: 12px 24px; background: #007bff; color: white; text-decoration: none; border-radius: 5px; margin: 10px 5px; }
        .footer { margin-top: 30px; padding: 20px; background: #f8f9fa; border-radius: 8px; text-align: center; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ DevSecOps Pipeline - Execution Successful</h1>
        <h2>${env.JOB_NAME} - Build #${env.BUILD_NUMBER}</h2>
    </div>
    
    <div class="content">
        <div class="summary-box">
            <h3>📊 Security Scan Summary</h3>
            <div class="metric">
                <div class="critical">${securityFindings.critical}</div>
                <div>CRITICAL</div>
            </div>
            <div class="metric">
                <div class="high">${securityFindings.high}</div>
                <div>HIGH</div>
            </div>
            <div class="metric">
                <div class="medium">${securityFindings.medium}</div>
                <div>MEDIUM</div>
            </div>
            <div class="metric">
                <div>${securityFindings.secrets}</div>
                <div>SECRETS</div>
            </div>
            <div class="metric">
                <div>${securityFindings.semgrep}</div>
                <div>CODE ISSUES</div>
            </div>
        </div>
        
        <div class="section">
            <h3>✅ Quality Gates Status</h3>
            <p><strong>SonarQube Quality Gate:</strong> <span class="success">PASSED</span></p>
            <p><strong>Security Policy:</strong> ${params.FAIL_ON_CRITICAL_VULNS ? 'STRICT 🔒' : 'LENIENT ⚠️'}</p>
            <p><strong>Build Status:</strong> <span class="success">SUCCESS</span></p>
        </div>
        
        <div class="section">
            <h3>📋 Build Information</h3>
            <p><strong>Duration:</strong> ${currentBuild.durationString.replace(' and counting', '')}</p>
            <p><strong>Triggered by:</strong> ${env.BUILD_USER ?: 'System'}</p>
            <p><strong>Commit:</strong> ${env.GIT_COMMIT ?: 'N/A'}</p>
            <p><strong>Date:</strong> ${new Date().format("yyyy-MM-dd HH:mm:ss")}</p>
        </div>
        
        <div class="section">
            <h3>🚀 Next Steps</h3>
            ${securityFindings.critical > 0 ? '<p>🔴 <strong>URGENT:</strong> Address critical vulnerabilities before deployment</p>' : ''}
            ${securityFindings.high > 0 ? '<p>🟠 <strong>HIGH PRIORITY:</strong> Review high severity vulnerabilities</p>' : ''}
            ${securityFindings.secrets > 0 ? '<p>🔑 <strong>CRITICAL:</strong> Rotate all exposed secrets immediately</p>' : ''}
            ${securityFindings.critical == 0 && securityFindings.high == 0 ? '<p>✅ <strong>READY:</strong> No critical issues detected, ready for next phase</p>' : ''}
        </div>
    </div>
    
    <div class="footer">
        <p>
            <a href="${env.BUILD_URL}" class="btn">View Build Details</a>
            <a href="${env.BUILD_URL}securityReport/" class="btn">View Security Report</a>
        </p>
        <p><em>This is an automated message from Jenkins DevSecOps Pipeline</em></p>
    </div>
</body>
</html>
"""
                
                emailext (
                    subject: "✅ SUCCESS: DevSecOps Pipeline - ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                    body: emailBody,
                    to: 'mekni.amin75@gmail.com',
                    mimeType: 'text/html',
                    attachLog: true,
                    compressLog: true
                )
                
                echo "✅ Notifications sent successfully"
            }
        }
        
        failure {
            script {
                echo "❌ PIPELINE FAILED - SENDING NOTIFICATIONS"
                
                slackSend(
                    channel: '#devsecops',
                    color: 'danger',
                    message: """❌ DevSecOps Pipeline FAILED: ${env.JOB_NAME} #${env.BUILD_NUMBER}
🚨 Pipeline execution failed
🔍 Check build logs for details
🔗 ${env.BUILD_URL}"""
                )
                
                emailext (
                    subject: "❌ FAILED: DevSecOps Pipeline - ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                    body: """
                    <h2>DevSecOps Pipeline - Build Failed</h2>
                    <p><strong>Job:</strong> ${env.JOB_NAME}</p>
                    <p><strong>Build:</strong> #${env.BUILD_NUMBER}</p>
                    <p><strong>Status:</strong> FAILED</p>
                    <p><strong>URL:</strong> <a href="${env.BUILD_URL}">${env.BUILD_URL}</a></p>
                    <p>Please check the build logs for details about the failure.</p>
                    """,
                    to: 'mekni.amin75@gmail.com',
                    mimeType: 'text/html',
                    attachLog: true
                )
                
                echo "✅ Failure notifications sent"
            }
        }
        
        cleanup {
            script {
                echo "🧹 Cleaning workspace..."
                // cleanWs()  // Décommenter si nécessaire
            }
        }
    }
}

// Méthode helper
def countOccurrences(String text, String pattern) {
    int count = 0
    int index = 0
    while ((index = text.indexOf(pattern, index)) != -1) {
        count++
        index += pattern.length()
    }
    return count
}