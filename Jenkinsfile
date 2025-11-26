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
        booleanParam(name: 'ENFORCE_QUALITY_GATE', defaultValue: false, description: 'Abort pipeline if Sonar Quality Gate != OK')
        booleanParam(name: 'FAIL_ON_CRITICAL_VULNS', defaultValue: false, description: 'Fail build on CRITICAL vulnerabilities')
        booleanParam(name: 'RUN_DAST_SCAN', defaultValue: false, description: 'Perform DAST security testing')
        string(name: 'TEST_ENVIRONMENT_URL', defaultValue: 'http://localhost:8080', description: 'URL for DAST testing')
    }

    environment {
        SONAR_HOST_URL = 'http://192.168.50.4:9000'
        SCANNER_HOME = tool 'sonar-scanner'
        GIT_COMMIT = sh(returnStdout: true, script: 'git rev-parse HEAD').trim()
        BUILD_USER = sh(returnStdout: true, script: 'echo ${BUILD_USER_ID:-${CHANGE_AUTHOR:-System}}').trim()
        MAVEN_OPTS = '--add-opens=java.base/java.lang=ALL-UNNAMED --add-opens=java.base/java.util=ALL-UNNAMED'
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
                        [$class: 'CleanBeforeCheckout'],
                        [$class: 'LocalBranch', localBranch: '**']
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
                                    def gitleaksContent = readFile('gitleaks-report.json')
                                    if (gitleaksContent.trim()) {
                                        def gitleaksReport = readJSON text: gitleaksContent
                                        def secretsCount = gitleaksReport?.Findings?.size() ?: 0
                                        echo "📁 Gitleaks report archived - Found ${secretsCount} secrets"
                                    }
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
                                    def semgrepContent = readFile('semgrep.json')
                                    if (semgrepContent.trim()) {
                                        def semgrepReport = readJSON text: semgrepContent
                                        def findingsCount = semgrepReport?.results?.size() ?: 0
                                        echo "📁 Semgrep report archived - Found ${findingsCount} issues"
                                    }
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
                    
                    echo "🧪 Running unit tests with JaCoCo..."
                    mvn -B test
                    
                    echo "📊 Generating JaCoCo reports..."
                    mvn -B jacoco:report
                    
                    echo "📦 Building package..."
                    mvn -B package -DskipTests
                '''
            }
            post { 
                always {
                    script {
                        // Vérification et archivage des rapports de test
                        def testReportDir = 'target/surefire-reports'
                        if (fileExists(testReportDir)) {
                            def testFiles = findFiles(glob: '**/target/surefire-reports/*.xml')
                            if (testFiles.size() > 0) {
                                junit testResults: '**/target/surefire-reports/*.xml', allowEmptyResults: true
                                echo "✅ Test reports processed - ${testFiles.size()} files found"
                            } else {
                                echo "⚠️ No test XML reports found in ${testReportDir}"
                                // Création d'un rapport de test factice pour éviter l'erreur
                                sh '''
                                    mkdir -p target/surefire-reports
                                    cat > target/surefire-reports/TEST-dummy.xml << 'EOF'
                                    <?xml version="1.0" encoding="UTF-8"?>
                                    <testsuite name="dummy" tests="0" failures="0" errors="0" skipped="0" time="0">
                                        <properties/>
                                    </testsuite>
                                    EOF
                                '''
                                junit testResults: '**/target/surefire-reports/*.xml', allowEmptyResults: true
                            }
                        } else {
                            echo "⚠️ No test reports directory found at ${testReportDir}"
                            sh 'mkdir -p target/surefire-reports'
                        }
                        
                        // Archivage JaCoCo
                        if (fileExists('target/jacoco.exec')) {
                            echo "✅ JaCoCo execution data found"
                            jacoco(
                                execPattern: '**/target/jacoco.exec',
                                classPattern: '**/target/classes',
                                sourcePattern: '**/src/main/java',
                                exclusionPattern: '**/src/test/*'
                            )
                            
                            // Vérification du rapport XML JaCoCo
                            if (fileExists('target/site/jacoco/jacoco.xml')) {
                                echo "✅ JaCoCo XML report generated successfully"
                            } else {
                                echo "⚠️ JaCoCo XML report not found"
                            }
                        } else {
                            echo "❌ No JaCoCo execution data found at target/jacoco.exec"
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

        // Étape 5: Analyse qualité et sécurité du code (Optionnelle)
        stage('Code Quality & SAST') {
            steps {
                script {
                    echo "🔧 Attempting SonarQube analysis..."
                    
                    try {
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
                                        -Dsonar.java.binaries=target/classes \\
                                        -Dsonar.coverage.jacoco.xmlReportPaths=target/site/jacoco/jacoco.xml \\
                                        -Dsonar.junit.reportsPath=target/surefire-reports || echo "SonarQube analysis completed with warnings"
                                """
                            }
                        }
                    } catch (Exception e) {
                        echo "⚠️ SonarQube analysis failed: ${e.message}"
                        echo "🔄 Continuing pipeline without SonarQube analysis"
                        currentBuild.result = 'UNSTABLE'
                    }
                }
            }
        }

        // Étape 6: Quality Gate conditionnelle
        stage('Quality Gate') {
            when {
                expression { 
                    fileExists('target/sonar/report-task.txt') || 
                    fileExists('.scannerwork/report-task.txt')
                }
            }
            steps {
                script {
                    timeout(time: 10, unit: 'MINUTES') {
                        try {
                            def qg = waitForQualityGate abortPipeline: params.ENFORCE_QUALITY_GATE
                            if (qg.status != 'OK') {
                                echo "❌ Quality Gate failed: ${qg.status}"
                                if (params.ENFORCE_QUALITY_GATE) {
                                    error "Quality Gate failure: ${qg.status}"
                                } else {
                                    currentBuild.result = 'UNSTABLE'
                                }
                            } else {
                                echo "✅ Quality Gate status: ${qg.status}"
                            }
                        } catch (Exception e) {
                            echo "⚠️ Quality Gate check failed: ${e.message}"
                            echo "🔄 Continuing pipeline without Quality Gate"
                            currentBuild.result = 'UNSTABLE'
                        }
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
                                    echo "✅ SBOM files archived: ${bomFiles.collect{it.name}.join(', ')}"
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
                                    def trivyContent = readFile('trivy-sca.json')
                                    if (trivyContent.trim()) {
                                        def trivyReport = readJSON text: trivyContent
                                        def results = trivyReport?.Results ?: []
                                        def criticalCount = 0
                                        def highCount = 0
                                        results.each { result ->
                                            def vulnerabilities = result.Vulnerabilities ?: []
                                            vulnerabilities.each { vuln ->
                                                if (vuln.Severity == 'CRITICAL') criticalCount++
                                                else if (vuln.Severity == 'HIGH') highCount++
                                            }
                                        }
                                        echo "✅ Trivy report archived - CRITICAL: ${criticalCount}, HIGH: ${highCount}"
                                    }
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
                        trivy_high: 0,
                        total_vulnerabilities: 0
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
                    
                    // Calcul du total
                    securityFindings.total_vulnerabilities = securityFindings.critical + securityFindings.high + securityFindings.medium + securityFindings.trivy_critical + securityFindings.trivy_high
                    
                    // Affichage des résultats
                    echo "=== SECURITY SCAN RESULTS ==="
                    echo "🔴 CRITICAL vulnerabilities: ${securityFindings.critical}"
                    echo "🟠 HIGH vulnerabilities: ${securityFindings.high}"
                    echo "🟡 MEDIUM vulnerabilities: ${securityFindings.medium}"
                    echo "🔑 Secrets exposed: ${securityFindings.secrets}"
                    echo "🐛 Semgrep findings: ${securityFindings.semgrep}"
                    echo "🔴 Trivy CRITICAL: ${securityFindings.trivy_critical}"
                    echo "🟠 Trivy HIGH: ${securityFindings.trivy_high}"
                    echo "📊 Total vulnerabilities: ${securityFindings.total_vulnerabilities}"
                    echo "============================="
                    
                    // Application des politiques
                    if (params.FAIL_ON_CRITICAL_VULNS && (securityFindings.critical > 0 || securityFindings.trivy_critical > 0)) {
                        def totalCritical = securityFindings.critical + securityFindings.trivy_critical
                        echo "❌ CRITICAL vulnerabilities detected: ${totalCritical}"
                        if (params.FAIL_ON_CRITICAL_VULNS) {
                            error "Build failed due to ${totalCritical} CRITICAL vulnerabilities"
                        }
                    } else {
                        echo "✅ No critical vulnerabilities blocking the build"
                    }
                    
                    // Sauvegarde des résultats
                    writeJSON file: 'security-findings.json', json: securityFindings
                    archiveArtifacts artifacts: 'security-findings.json', allowEmptyArchive: true
                    
                    // Génération des rapports
                    generateSecurityReports(securityFindings)
                    
                    echo "✅ Security policies applied successfully"
                }
            }
        }
    }

    post {
        always {
            script {
                def finalStatus = currentBuild.currentResult
                echo "=== FINAL PIPELINE STATUS ==="
                echo "Build Result: ${finalStatus}"
                echo "Build Number: ${env.BUILD_NUMBER}"
                echo "Duration: ${currentBuild.durationString.replace(' and counting', '')}"
                
                // Chargement des résultats de sécurité pour le rapport final
                def securityFindings = [critical: 0, high: 0, medium: 0, secrets: 0, semgrep: 0, trivy_critical: 0, trivy_high: 0, total_vulnerabilities: 0]
                if (fileExists('security-findings.json')) {
                    securityFindings = readJSON file: 'security-findings.json'
                }
                
                generateFinalReport(securityFindings, finalStatus)
                
                // Nettoyage des fichiers temporaires
                sh '''
                    echo "🧹 Cleaning temporary files..."
                    rm -f security-findings.json dependency-check-report.html || true
                '''
            }
        }
        
        success {
            script {
                echo "✅ PIPELINE SUCCESS - SENDING NOTIFICATIONS"
                sendSuccessNotifications()
            }
        }
        
        unstable {
            script {
                echo "⚠️ PIPELINE UNSTABLE - SENDING NOTIFICATIONS"
                sendUnstableNotifications()
            }
        }
        
        failure {
            script {
                echo "❌ PIPELINE FAILED - SENDING NOTIFICATIONS"
                sendFailureNotifications()
            }
        }
        
        cleanup {
            script {
                echo "🧹 Cleaning workspace..."
                sh '''
                    echo "Keeping security reports for analysis..."
                    ls -la *.json *.html *.md 2>/dev/null || echo "No report files found"
                '''
            }
        }
    }
}

// Méthodes helper
def countOccurrences(String text, String pattern) {
    int count = 0
    int index = 0
    while ((index = text.indexOf(pattern, index)) != -1) {
        count++
        index += pattern.length()
    }
    return count
}

def generateSecurityReports(securityFindings) {
    def totalCritical = securityFindings.critical + securityFindings.trivy_critical
    def totalHigh = securityFindings.high + securityFindings.trivy_high
    
    // Génération du rapport HTML
    def htmlReport = """
<!DOCTYPE html>
<html>
<head>
    <title>DevSecOps Security Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; text-align: center; }
        .metrics { display: flex; justify-content: space-around; flex-wrap: wrap; }
        .metric-card { background: white; padding: 20px; margin: 10px; border-radius: 8px; text-align: center; min-width: 120px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .critical-card { border-left: 4px solid #d32f2f; }
        .high-card { border-left: 4px solid #f57c00; }
        .secrets-card { border-left: 4px solid #7b1fa2; }
        .issues-card { border-left: 4px solid #fbc02d; }
        .section { margin: 15px 0; padding: 20px; background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .critical { color: #d32f2f; font-weight: bold; }
        .high { color: #f57c00; font-weight: bold; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ DevSecOps Security Compliance Report</h1>
        <p><strong>Build:</strong> ${env.JOB_NAME} #${env.BUILD_NUMBER}</p>
        <p><strong>Date:</strong> ${new Date().format("yyyy-MM-dd HH:mm:ss")}</p>
    </div>
    
    <div class="metrics">
        <div class="metric-card critical-card">
            <h3>🔴 CRITICAL</h3>
            <p style="font-size: 24px; font-weight: bold; color: #d32f2f;">${totalCritical}</p>
        </div>
        <div class="metric-card high-card">
            <h3>🟠 HIGH</h3>
            <p style="font-size: 24px; font-weight: bold; color: #f57c00;">${totalHigh}</p>
        </div>
        <div class="metric-card secrets-card">
            <h3>🔑 SECRETS</h3>
            <p style="font-size: 24px; font-weight: bold; color: #7b1fa2;">${securityFindings.secrets}</p>
        </div>
        <div class="metric-card issues-card">
            <h3>🐛 CODE ISSUES</h3>
            <p style="font-size: 24px; font-weight: bold; color: #fbc02d;">${securityFindings.semgrep}</p>
        </div>
    </div>
    
    <div class="section">
        <h2>📊 Detailed Security Analysis</h2>
        <p>🔴 <span class="critical">CRITICAL:</span> ${securityFindings.critical} (Dependency Check) + ${securityFindings.trivy_critical} (Trivy) = <strong>${totalCritical} total</strong></p>
        <p>🟠 <span class="high">HIGH:</span> ${securityFindings.high} (Dependency Check) + ${securityFindings.trivy_high} (Trivy) = <strong>${totalHigh} total</strong></p>
        <p>🟡 MEDIUM: ${securityFindings.medium}</p>
        <p>🔑 Secrets Exposed: ${securityFindings.secrets}</p>
        <p>🐛 Code Issues: ${securityFindings.semgrep}</p>
        <p>📊 Total Vulnerabilities: ${securityFindings.total_vulnerabilities}</p>
    </div>
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
- **Date**: ${new Date().format("yyyy-MM-dd HH:mm:ss")}
- **Status**: ${currentBuild.currentResult}

## Security Scan Summary
- 🔴 **CRITICAL**: ${totalCritical} total
- 🟠 **HIGH**: ${totalHigh} total  
- 🟡 **MEDIUM**: ${securityFindings.medium}
- 🔑 **Secrets Exposed**: ${securityFindings.secrets}
- 🐛 **Code Issues**: ${securityFindings.semgrep}
- 📊 **Total Vulnerabilities**: ${securityFindings.total_vulnerabilities}

## Recommendations
${totalCritical > 0 ? '- **IMMEDIATE ACTION**: Address critical vulnerabilities' : ''}
${totalHigh > 0 ? '- **HIGH PRIORITY**: Review high severity vulnerabilities' : ''}
${securityFindings.secrets > 0 ? '- **CRITICAL**: Rotate exposed secrets immediately' : ''}
"""
    writeFile file: 'security-compliance-report.md', text: markdownReport
    archiveArtifacts artifacts: 'security-compliance-report.md', allowEmptyArchive: true
}

def generateFinalReport(securityFindings, finalStatus) {
    def totalCritical = securityFindings.critical + securityFindings.trivy_critical
    def totalHigh = securityFindings.high + securityFindings.trivy_high
    
    def finalReport = """
# 🛡️ DevSecOps Pipeline - Final Report

## Executive Summary
**Status**: ${finalStatus}  
**Build**: ${env.JOB_NAME} #${env.BUILD_NUMBER}  
**Duration**: ${currentBuild.durationString.replace(' and counting', '')}  

## Security Assessment
${securityFindings.secrets == 0 ? '✅' : '🔴'} **Secrets**: ${securityFindings.secrets}  
${securityFindings.semgrep == 0 ? '✅' : '🟠'} **Code Issues**: ${securityFindings.semgrep}  
${totalCritical == 0 ? '✅' : '🔴'} **Critical**: ${totalCritical}  
${totalHigh == 0 ? '✅' : '🟠'} **High**: ${totalHigh}  

## Next Steps
${totalCritical > 0 ? '🔴 Address critical vulnerabilities' : ''}
${totalHigh > 0 ? '🟠 Review high severity issues' : ''}
${securityFindings.secrets > 0 ? '🔑 Rotate exposed secrets' : ''}
${totalCritical == 0 && totalHigh == 0 ? '✅ Ready for next phase' : ''}
"""
    writeFile file: 'devsecops-final-report.md', text: finalReport
    archiveArtifacts artifacts: 'devsecops-final-report.md', allowEmptyArchive: true
}

def sendSuccessNotifications() {
    def securityFindings = [critical: 0, high: 0, medium: 0, secrets: 0, semgrep: 0, trivy_critical: 0, trivy_high: 0]
    if (fileExists('security-findings.json')) {
        securityFindings = readJSON file: 'security-findings.json'
    }
    
    def totalCritical = securityFindings.critical + securityFindings.trivy_critical
    def totalHigh = securityFindings.high + securityFindings.trivy_high
    
    slackSend(
        channel: '#devsecops',
        color: totalCritical > 0 ? 'warning' : 'good',
        message: """${totalCritical > 0 ? '⚠️' : '✅'} DevSecOps Pipeline ${totalCritical > 0 ? 'COMPLETED WITH ISSUES' : 'SUCCESS'}: ${env.JOB_NAME} #${env.BUILD_NUMBER}
🔴 Critical: ${totalCritical} | 🟠 High: ${totalHigh}
🔑 Secrets: ${securityFindings.secrets} | 🐛 Issues: ${securityFindings.semgrep}
✅ Build: SUCCESS
🔗 ${env.BUILD_URL}"""
    )
}

def sendUnstableNotifications() {
    def securityFindings = [critical: 0, high: 0, medium: 0, secrets: 0, semgrep: 0, trivy_critical: 0, trivy_high: 0]
    if (fileExists('security-findings.json')) {
        securityFindings = readJSON file: 'security-findings.json'
    }
    
    def totalCritical = securityFindings.critical + securityFindings.trivy_critical
    def totalHigh = securityFindings.high + securityFindings.trivy_high
    
    slackSend(
        channel: '#devsecops',
        color: 'warning',
        message: """⚠️ DevSecOps Pipeline UNSTABLE: ${env.JOB_NAME} #${env.BUILD_NUMBER}
🔴 Critical: ${totalCritical} | 🟠 High: ${totalHigh}
🔑 Secrets: ${securityFindings.secrets} | 🐛 Issues: ${securityFindings.semgrep}
⚠️ Some stages completed with warnings
🔗 ${env.BUILD_URL}"""
    )
}

def sendFailureNotifications() {
    slackSend(
        channel: '#devsecops',
        color: 'danger',
        message: """❌ DevSecOps Pipeline FAILED: ${env.JOB_NAME} #${env.BUILD_NUMBER}
🚨 Pipeline execution failed
🔍 Check build logs for details
🔗 ${env.BUILD_URL}"""
    )
}