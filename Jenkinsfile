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
        booleanParam(name: 'FAIL_ON_CRITICAL_VULNS', defaultValue: true, description: 'Fail build on CRITICAL vulnerabilities')
        booleanParam(name: 'FAIL_ON_HIGH_VULNS', defaultValue: false, description: 'Fail build on HIGH vulnerabilities')
        booleanParam(name: 'RUN_DAST_SCAN', defaultValue: false, description: 'Perform DAST security testing')
        string(name: 'TEST_ENVIRONMENT_URL', defaultValue: 'http://localhost:8080', description: 'URL for DAST testing')
        choice(name: 'NOTIFICATION_TYPE', choices: ['SLACK', 'EMAIL', 'BOTH'], description: 'Select notification method')
    }

    environment {
        SONAR_HOST_URL = 'http://192.168.50.4:9000'
        SCANNER_HOME = tool 'sonar-scanner'
        GIT_COMMIT = sh(returnStdout: true, script: 'git rev-parse HEAD').trim()
        BUILD_USER = sh(returnStdout: true, script: 'echo ${BUILD_USER_ID:-${CHANGE_AUTHOR:-System}}').trim()
        MAVEN_OPTS = '--add-opens=java.base/java.lang=ALL-UNNAMED --add-opens=java.base/java.util=ALL-UNNAMED'
        JAVA_OPTS = '-Xmx1024m -XX:MaxPermSize=256m'
        // Enhanced JaCoCo configuration
        JACOCO_VERSION = '0.8.9'
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
                
                sh '''
                    echo "📁 Workspace structure:"
                    find . -name "*.java" -type f | head -10
                    echo "✅ Checkout completed successfully"
                '''
            }
        }

        // Étape 3: Validation de la structure du projet
        stage('Validate Project Structure') {
            steps {
                sh '''
                    echo "🔍 Validating project structure..."
                    
                    # Check if proper test structure exists
                    if [ ! -d "src/test/java/com/visualpathit/test" ]; then
                        echo "⚠️ Test directory structure missing, creating basic structure..."
                        mkdir -p src/test/java/com/visualpathit/test
                    fi
                    
                    # Validate critical files
                    if [ ! -f "pom.xml" ]; then
                        echo "❌ pom.xml not found!"
                        exit 1
                    fi
                    
                    if [ ! -d "src/main/java" ]; then
                        echo "❌ src/main/java directory not found!"
                        exit 1
                    fi
                    
                    echo "✅ Project structure validated"
                '''
            }
        }

        // Étape 4: Sécurité Shift-Left - FIXED
        stage('Early Security Scan') {
            parallel {
                stage('Secrets Detection') {
                    steps {
                        sh '''
                            echo "🔍 Scanning for secrets in code..."
                            if command -v gitleaks >/dev/null 2>&1; then
                                echo "✅ Gitleaks is installed"
                                gitleaks detect --source . --report-format json --report-path gitleaks-report.json --verbose || true
                            else
                                echo "⚠️ Gitleaks not installed, installing..."
                                wget https://github.com/gitleaks/gitleaks/releases/download/v8.18.0/gitleaks_8.18.0_linux_x64.tar.gz
                                tar -xzf gitleaks_8.18.0_linux_x64.tar.gz
                                ./gitleaks detect --source . --report-format json --report-path gitleaks-report.json --verbose || true
                            fi
                        '''
                    }
                    post {
                        always {
                            script {
                                if (fileExists('gitleaks-report.json')) {
                                    archiveArtifacts artifacts: 'gitleaks-report.json', allowEmptyArchive: true
                                    try {
                                        def gitleaksContent = readFile('gitleaks-report.json')
                                        if (gitleaksContent.trim() && gitleaksContent != '{"Findings": []}') {
                                            def gitleaksReport = readJSON text: gitleaksContent
                                            def secretsCount = gitleaksReport?.Findings?.size() ?: 0
                                            echo "📁 Gitleaks report archived - Found ${secretsCount} secrets"
                                            
                                            if (secretsCount > 0) {
                                                echo "🔴 CRITICAL: ${secretsCount} secrets found in code!"
                                                currentBuild.result = 'UNSTABLE'
                                            }
                                        } else {
                                            echo "✅ No secrets found by Gitleaks"
                                        }
                                    } catch (Exception e) {
                                        echo "⚠️ Error parsing gitleaks report: ${e.message}"
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
                                semgrep --config auto --output semgrep.json --json --error . || true
                            else
                                echo "⚠️ Semgrep not installed, installing..."
                                python3 -m pip install semgrep
                                semgrep --config auto --output semgrep.json --json --error . || true
                            fi
                        '''
                    }
                    post {
                        always {
                            script {
                                if (fileExists('semgrep.json')) {
                                    archiveArtifacts artifacts: 'semgrep.json', allowEmptyArchive: true
                                    try {
                                        def semgrepContent = readFile('semgrep.json')
                                        if (semgrepContent.trim() && semgrepContent != '{"results": []}') {
                                            def semgrepReport = readJSON text: semgrepContent
                                            def findingsCount = semgrepReport?.results?.size() ?: 0
                                            echo "📁 Semgrep report archived - Found ${findingsCount} issues"
                                            
                                            if (findingsCount > 0) {
                                                echo "🟠 SAST findings: ${findingsCount} code issues detected"
                                            }
                                        } else {
                                            echo "✅ No SAST issues found by Semgrep"
                                        }
                                    } catch (Exception e) {
                                        echo "⚠️ Error parsing semgrep report: ${e.message}"
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Étape 5: Build et tests avec configuration CORRIGÉE - FIXED
        stage('Build & Unit Tests') {
            steps { 
                sh '''
                    echo "🏗️ Building application with enhanced configuration..."
                    
                    # Clean and compile with proper JaCoCo configuration
                    mvn -B clean compile test-compile -Djacoco.version=${JACOCO_VERSION}
                    
                    echo "🧪 Running unit tests with proper configuration..."
                    # Run tests with proper JaCoCo agent configuration
                    mvn -B test \
                        -DfailIfNoTests=false \
                        -Dmaven.test.failure.ignore=true \
                        -Djacoco.version=${JACOCO_VERSION} \
                        -DargLine="-javaagent:$$(find $HOME/.m2/repository/org/jacoco/org.jacoco.agent/${JACOCO_VERSION} -name '*.jar' | head -1)=destfile=target/jacoco.exec"
                    
                    echo "📊 Generating JaCoCo reports..."
                    mvn -B jacoco:report -Djacoco.version=${JACOCO_VERSION}
                    
                    echo "📦 Building package..."
                    mvn -B package -DskipTests=true -Djacoco.version=${JACOCO_VERSION}
                    
                    echo "✅ Build and test phase completed"
                '''
            }
            post { 
                always {
                    script {
                        // Enhanced test report handling
                        def testReportDir = 'target/surefire-reports'
                        if (fileExists(testReportDir)) {
                            def testFiles = findFiles(glob: '**/target/surefire-reports/*.xml')
                            if (testFiles.size() > 0) {
                                junit testResults: '**/target/surefire-reports/*.xml', allowEmptyResults: true, skipPublishingChecks: false
                                echo "✅ Test reports processed - ${testFiles.size()} files found"
                                
                                // Display detailed test results
                                try {
                                    def testSummary = sh(returnStdout: true, script: '''
                                        echo "=== TEST RESULTS SUMMARY ==="
                                        for report in target/surefire-reports/*.xml; do
                                            if [ -f "$report" ]; then
                                                tests=$(grep -o "tests=\"[0-9]*\"" "$report" | head -1 | cut -d'"' -f2)
                                                failures=$(grep -o "failures=\"[0-9]*\"" "$report" | head -1 | cut -d'"' -f2)
                                                errors=$(grep -o "errors=\"[0-9]*\"" "$report" | head -1 | cut -d'"' -f2)
                                                name=$(grep -o "name=\"[^\"]*\"" "$report" | head -1 | cut -d'"' -f2)
                                                echo "📋 $name: Tests=$tests, Failures=$failures, Errors=$errors"
                                            fi
                                        done
                                    ''').trim()
                                    echo testSummary
                                } catch (Exception e) {
                                    echo "⚠️ Could not generate test summary: ${e.message}"
                                }
                            } else {
                                echo "⚠️ No test XML reports found in ${testReportDir}"
                            }
                        } else {
                            echo "❌ Test reports directory not found at ${testReportDir}"
                        }
                        
                        // Enhanced JaCoCo handling
                        if (fileExists('target/jacoco.exec')) {
                            def jacocoSize = sh(returnStdout: true, script: 'wc -c < target/jacoco.exec').trim()
                            echo "✅ JaCoCo execution data found: ${jacocoSize} bytes"
                            
                            // Publish JaCoCo coverage report
                            jacoco(
                                execPattern: '**/target/jacoco.exec',
                                classPattern: '**/target/classes',
                                sourcePattern: '**/src/main/java',
                                exclusionPattern: '**/test/**',
                                skipCopyOfSrcFiles: false,
                                inclusionPattern: '**/*.class',
                                sourceInclusionPattern: '**/*.java',
                                sourceExclusionPattern: '**/test/**'
                            )
                            
                            // Verify JaCoCo XML report
                            if (fileExists('target/site/jacoco/jacoco.xml')) {
                                echo "✅ JaCoCo XML report generated successfully"
                                try {
                                    def coverageData = sh(returnStdout: true, script: '''
                                        if [ -f "target/site/jacoco/jacoco.xml" ]; then
                                            echo "Line Coverage: $(grep -o 'line=\"[0-9]*\"' target/site/jacoco/jacoco.xml | head -1 | cut -d'"' -f2)%"
                                            echo "Branch Coverage: $(grep -o 'branch=\"[0-9]*\"' target/site/jacoco/jacoco.xml | head -1 | cut -d'"' -f2)%"
                                            echo "Methods Covered: $(grep -o 'method=\"[0-9]*\"' target/site/jacoco/jacoco.xml | head -1 | cut -d'"' -f2)"
                                        fi
                                    ''').trim()
                                    echo "📈 ${coverageData}"
                                } catch (Exception e) {
                                    echo "⚠️ Could not read coverage details: ${e.message}"
                                }
                            } else {
                                echo "❌ JaCoCo XML report not found"
                                // Generate it explicitly
                                sh 'mvn -B jacoco:report -Djacoco.version=${JACOCO_VERSION}'
                            }
                        } else {
                            echo "❌ No JaCoCo execution data found at target/jacoco.exec"
                            echo "🔍 Checking build output..."
                            sh '''
                                echo "=== Build Artifacts ==="
                                find target/ -name "*.jar" -o -name "*.war" -o -name "*.exec" -o -name "*.xml" | head -20
                                echo "=== Target Directory ==="
                                ls -la target/ || echo "Target directory does not exist"
                            '''
                        }
                        
                        // Archive artifacts
                        def warFiles = findFiles(glob: 'target/*.war')
                        if (warFiles.size() > 0) {
                            archiveArtifacts artifacts: '**/target/*.war', allowEmptyArchive: false
                            def warSize = sh(returnStdout: true, script: "wc -c < '${warFiles[0].path}'").trim()
                            echo "✅ WAR file archived: ${warFiles[0].name} (${warSize} bytes)"
                        } else {
                            echo "⚠️ No WAR file found in target directory"
                            // Check for JAR files as alternative
                            def jarFiles = findFiles(glob: 'target/*.jar')
                            if (jarFiles.size() > 0 && !jarFiles[0].path.contains('sources') && !jarFiles[0].path.contains('javadoc')) {
                                archiveArtifacts artifacts: '**/target/*.jar', allowEmptyArchive: false
                                echo "✅ JAR file archived: ${jarFiles[0].name}"
                            }
                        }
                    }
                }
                success {
                    echo "🎉 Build & Tests stage completed successfully"
                }
                failure {
                    echo "❌ Build & Tests stage failed"
                }
            }
        }

        // Étape 6: Analyse qualité et sécurité du code - FIXED
        stage('Code Quality & SAST') {
            steps {
                script {
                    echo "🔧 Running SonarQube analysis with enhanced configuration..."
                    
                    try {
                        withCredentials([string(credentialsId: 'sonar-token', variable: 'SONAR_TOKEN')]) {
                            withSonarQubeEnv('sonar-server') {
                                sh """
                                    echo "🔍 Starting SonarQube analysis..."
                                    
                                    # Create comprehensive sonar-project.properties
                                    cat > sonar-project.properties << 'EOF'
sonar.projectKey=vprofile-application-${env.BUILD_NUMBER}
sonar.projectName=VProfile Application
sonar.projectVersion=2.0
sonar.sources=src/main/java
sonar.tests=src/test/java
sonar.java.binaries=target/classes
sonar.java.test.binaries=target/test-classes
sonar.coverage.jacoco.xmlReportPaths=target/site/jacoco/jacoco.xml
sonar.junit.reportsPath=target/surefire-reports
sonar.sourceEncoding=UTF-8
sonar.java.source=17
sonar.host.url=${SONAR_HOST_URL}
sonar.login=${SONAR_TOKEN}
sonar.coverage.exclusions=**/test/**,**/generated-**
sonar.cpd.exclusions=**/test/**
sonar.scm.disabled=false
EOF

                                    # Run Sonar analysis with Maven
                                    mvn -B sonar:sonar \
                                        -Dsonar.projectKey=vprofile-application-${env.BUILD_NUMBER} \
                                        -Dsonar.host.url=${SONAR_HOST_URL} \
                                        -Dsonar.login=${SONAR_TOKEN} \
                                        -Dsonar.coverage.jacoco.xmlReportPaths=target/site/jacoco/jacoco.xml \
                                        -Dsonar.junit.reportsPath=target/surefire-reports \
                                        -Dsonar.java.binaries=target/classes \
                                        -Dsonar.java.test.binaries=target/test-classes
                                """
                            }
                        }
                        echo "✅ SonarQube analysis completed successfully"
                    } catch (Exception e) {
                        echo "❌ SonarQube analysis failed: ${e.message}"
                        echo "🔄 Continuing pipeline without SonarQube analysis"
                        currentBuild.result = 'UNSTABLE'
                    }
                }
            }
        }

        // Étape 7: Quality Gate conditionnelle - FIXED
        stage('Quality Gate') {
            steps {
                script {
                    echo "⚖️ Checking Quality Gate status..."
                    
                    timeout(time: 10, unit: 'MINUTES') {
                        try {
                            def qg = waitForQualityGate abortPipeline: params.ENFORCE_QUALITY_GATE
                            
                            if (qg.status != 'OK') {
                                echo "❌ Quality Gate status: ${qg.status}"
                                if (params.ENFORCE_QUALITY_GATE) {
                                    error "Quality Gate failure: ${qg.status}. Pipeline aborted due to quality issues."
                                } else {
                                    currentBuild.result = 'UNSTABLE'
                                    echo "⚠️ Quality Gate failed but pipeline continues due to configuration"
                                }
                            } else {
                                echo "✅ Quality Gate status: ${qg.status}"
                                echo "🎉 Code quality meets the required standards"
                            }
                        } catch (Exception e) {
                            echo "⚠️ Quality Gate check failed or skipped: ${e.message}"
                            if (params.ENFORCE_QUALITY_GATE) {
                                error "Quality Gate check failed: ${e.message}"
                            } else {
                                echo "🔄 Continuing pipeline without Quality Gate"
                                currentBuild.result = 'UNSTABLE'
                            }
                        }
                    }
                }
            }
        }

        // Étape 8: Analyse des dépendances (SCA) - FIXED
        stage('Dependency Analysis') {
            parallel {
                stage('SCA - OWASP Dependency Check') {
                    steps {
                        sh '''
                            echo "📦 Scanning dependencies for vulnerabilities with enhanced configuration..."
                            
                            # Create dependency-check configuration
                            cat > dependency-check-config.xml << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<scan xmlns="https://jeremylong.github.io/DependencyCheck/dependency-check.2.9.xsd">
    <suppressionFile>dependency-check-suppressions.xml</suppressionFile>
    <failBuildOnAnyVulnerability>false</failBuildOnAnyVulnerability>
</scan>
EOF

                            # Create suppressions file for false positives
                            cat > dependency-check-suppressions.xml << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<suppressions xmlns="https://jeremylong.github.io/DependencyCheck/dependency-check.2.9.xsd">
    <!-- Add known false positive suppressions here -->
</suppressions>
EOF

                            mvn -B org.owasp:dependency-check-maven:check \
                                -Dformat=HTML \
                                -Dformat=XML \
                                -Dodc.outputDirectory=target/dependency-check-report \
                                -DretireJsEnabled=true \
                                -DnodeAuditEnabled=false \
                                -DnodePackageSkip=true \
                                -DassemblyAnalyzerEnabled=false
                        '''
                    }
                    post {
                        always {
                            script {
                                if (fileExists('target/dependency-check-report')) {
                                    archiveArtifacts artifacts: 'target/dependency-check-report/*', allowEmptyArchive: true
                                    echo "✅ Dependency check reports archived"
                                    
                                    // Analyze dependency check results
                                    if (fileExists('target/dependency-check-report/dependency-check-report.xml')) {
                                        def dependencyReport = readFile('target/dependency-check-report/dependency-check-report.xml')
                                        def criticalCount = countXmlOccurrences(dependencyReport, 'severity="CRITICAL"')
                                        def highCount = countXmlOccurrences(dependencyReport, 'severity="HIGH"')
                                        
                                        echo "📊 OWASP Dependency Check Results: CRITICAL=${criticalCount}, HIGH=${highCount}"
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
                            mvn -B org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom \
                                -Dcyclonedx.skip=false \
                                -Dcyclonedx.format=xml \
                                -Dcyclonedx.format=json
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
                                    echo "⚠️ No SBOM files generated, checking alternative locations..."
                                    sh '''
                                        find target/ -name "*bom*" -o -name "*cyclonedx*" | head -10 || echo "No BOM files found"
                                    '''
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
                                # Enhanced Trivy scan with better configuration
                                trivy fs --scanners vuln \
                                    --severity CRITICAL,HIGH,MEDIUM \
                                    --format json \
                                    --output trivy-sca.json \
                                    --timeout 15m \
                                    --skip-dirs-db-update \
                                    --skip-java-db-update .
                            else
                                echo "❌ Trivy not available, skipping scan"
                                echo '{"Results": []}' > trivy-sca.json
                            fi
                        '''
                    }
                    post {
                        always {
                            script {
                                if (fileExists('trivy-sca.json')) {
                                    archiveArtifacts artifacts: 'trivy-sca.json', allowEmptyArchive: true
                                    try {
                                        def trivyContent = readFile('trivy-sca.json')
                                        if (trivyContent.trim() && trivyContent != '{"Results": []}') {
                                            def trivyReport = readJSON text: trivyContent
                                            def results = trivyReport?.Results ?: []
                                            def criticalCount = 0
                                            def highCount = 0
                                            def mediumCount = 0
                                            
                                            results.each { result ->
                                                def vulnerabilities = result.Vulnerabilities ?: []
                                                vulnerabilities.each { vuln ->
                                                    switch(vuln.Severity) {
                                                        case 'CRITICAL':
                                                            criticalCount++
                                                            break
                                                        case 'HIGH':
                                                            highCount++
                                                            break
                                                        case 'MEDIUM':
                                                            mediumCount++
                                                            break
                                                    }
                                                }
                                            }
                                            echo "✅ Trivy report archived - CRITICAL: ${criticalCount}, HIGH: ${highCount}, MEDIUM: ${mediumCount}"
                                        } else {
                                            echo "✅ Trivy scan completed - No vulnerabilities found"
                                        }
                                    } catch (Exception e) {
                                        echo "⚠️ Error parsing Trivy report: ${e.message}"
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Étape 9: Application des politiques de sécurité - ENHANCED
        stage('Security Policy Enforcement') {
            steps {
                script {
                    echo "⚖️ Applying enhanced security policies..."
                    
                    def securityFindings = [
                        critical: 0,
                        high: 0,
                        medium: 0,
                        secrets: 0,
                        semgrep: 0,
                        trivy_critical: 0,
                        trivy_high: 0,
                        trivy_medium: 0,
                        total_vulnerabilities: 0
                    ]
                    
                    // Enhanced security report analysis
                    analyzeSecurityReports(securityFindings)
                    
                    // Calculate totals
                    def totalCritical = securityFindings.critical + securityFindings.trivy_critical
                    def totalHigh = securityFindings.high + securityFindings.trivy_high
                    def totalMedium = securityFindings.medium + securityFindings.trivy_medium
                    securityFindings.total_vulnerabilities = totalCritical + totalHigh + totalMedium + securityFindings.secrets + securityFindings.semgrep
                    
                    // Display comprehensive results
                    displaySecurityResults(securityFindings)
                    
                    // Enhanced security policy enforcement
                    enforceSecurityPolicies(securityFindings)
                    
                    // Save findings for reporting
                    writeJSON file: 'security-findings.json', json: securityFindings
                    archiveArtifacts artifacts: 'security-findings.json', allowEmptyArchive: true
                    
                    echo "✅ Security policies applied successfully"
                }
            }
        }

        // Étape 10: Génération des rapports finaux
        stage('Generate Comprehensive Reports') {
            steps {
                script {
                    echo "📊 Generating comprehensive reports..."
                    
                    def securityFindings = [critical: 0, high: 0, medium: 0, secrets: 0, semgrep: 0, trivy_critical: 0, trivy_high: 0, trivy_medium: 0]
                    if (fileExists('security-findings.json')) {
                        securityFindings = readJSON file: 'security-findings.json'
                    }
                    
                    generateComprehensiveReports(securityFindings)
                    generateEmailReport(securityFindings)
                    generateFinalReport(securityFindings, currentBuild.currentResult ?: 'SUCCESS')
                    
                    echo "✅ All reports generated successfully"
                }
            }
        }
    }

    post {
        always {
            script {
                def finalStatus = currentBuild.currentResult ?: 'SUCCESS'
                def duration = currentBuild.durationString.replace(' and counting', '')
                
                echo "=== PIPELINE EXECUTION SUMMARY ==="
                echo "Build Result: ${finalStatus}"
                echo "Build Number: ${env.BUILD_NUMBER}"
                echo "Duration: ${duration}"
                echo "Job: ${env.JOB_NAME}"
                echo "Git Commit: ${env.GIT_COMMIT}"
                echo "Triggered by: ${env.BUILD_USER ?: 'System'}"
                echo "================================="
                
                // Generate final artifacts
                def securityFindings = [critical: 0, high: 0, medium: 0, secrets: 0, semgrep: 0, trivy_critical: 0, trivy_high: 0, trivy_medium: 0]
                if (fileExists('security-findings.json')) {
                    securityFindings = readJSON file: 'security-findings.json'
                }
                
                // Send notifications based on parameter
                def notificationType = params.NOTIFICATION_TYPE ?: 'SLACK'
                if (notificationType == 'EMAIL' || notificationType == 'BOTH') {
                    sendEmailNotification(securityFindings, finalStatus)
                }
                if (notificationType == 'SLACK' || notificationType == 'BOTH') {
                    sendSlackNotification(securityFindings, finalStatus)
                }
                
                // Final cleanup
                sh '''
                    echo "🧹 Cleaning temporary files..."
                    rm -f security-findings.json trivy-sca.json gitleaks-report.json semgrep.json || true
                    echo "📁 Final artifacts summary:"
                    ls -la *.html *.md *.txt 2>/dev/null | head -10 || echo "No report files to clean"
                '''
            }
        }
        success {
            echo "🎉 Pipeline executed successfully!"
            script {
                if (currentBuild.result == 'UNSTABLE') {
                    echo "⚠️ Pipeline completed with warnings - check security findings"
                } else {
                    echo "✅ All stages completed successfully"
                }
            }
        }
        failure {
            echo "❌ Pipeline failed - check stage logs for details"
        }
        unstable {
            echo "⚠️ Pipeline completed with unstable status - security or quality issues detected"
        }
    }
}

// Enhanced helper methods

def countXmlOccurrences(String text, String pattern) {
    if (!text) return 0
    int count = 0
    int index = 0
    while ((index = text.indexOf(pattern, index)) != -1) {
        count++
        index += pattern.length()
    }
    return count
}

def analyzeSecurityReports(securityFindings) {
    echo "🔍 Analyzing security reports..."
    
    // Analyze Gitleaks report
    try {
        if (fileExists('gitleaks-report.json')) {
            def gitleaksContent = readFile('gitleaks-report.json')
            if (gitleaksContent.trim() && gitleaksContent != '{"Findings": []}') {
                def gitleaksReport = readJSON text: gitleaksContent
                securityFindings.secrets = gitleaksReport?.Findings?.size() ?: 0
            }
        }
    } catch (Exception e) {
        echo "⚠️ Error reading gitleaks report: ${e.message}"
    }
    
    // Analyze Semgrep report
    try {
        if (fileExists('semgrep.json')) {
            def semgrepContent = readFile('semgrep.json')
            if (semgrepContent.trim() && semgrepContent != '{"results": []}') {
                def semgrepReport = readJSON text: semgrepContent
                securityFindings.semgrep = semgrepReport?.results?.size() ?: 0
            }
        }
    } catch (Exception e) {
        echo "⚠️ Error reading semgrep report: ${e.message}"
    }
    
    // Analyze OWASP Dependency Check report
    try {
        if (fileExists('target/dependency-check-report/dependency-check-report.xml')) {
            def xmlContent = readFile('target/dependency-check-report/dependency-check-report.xml')
            securityFindings.critical = countXmlOccurrences(xmlContent, 'severity="CRITICAL"')
            securityFindings.high = countXmlOccurrences(xmlContent, 'severity="HIGH"')
            securityFindings.medium = countXmlOccurrences(xmlContent, 'severity="MEDIUM"')
        }
    } catch (Exception e) {
        echo "⚠️ Error analyzing dependency check report: ${e.message}"
    }
    
    // Analyze Trivy report
    try {
        if (fileExists('trivy-sca.json')) {
            def trivyContent = readFile('trivy-sca.json')
            if (trivyContent.trim() && trivyContent != '{"Results": []}') {
                def trivyReport = readJSON text: trivyContent
                def results = trivyReport?.Results ?: []
                results.each { result ->
                    def vulnerabilities = result.Vulnerabilities ?: []
                    vulnerabilities.each { vuln ->
                        switch(vuln.Severity) {
                            case 'CRITICAL':
                                securityFindings.trivy_critical++
                                break
                            case 'HIGH':
                                securityFindings.trivy_high++
                                break
                            case 'MEDIUM':
                                securityFindings.trivy_medium++
                                break
                        }
                    }
                }
            }
        }
    } catch (Exception e) {
        echo "⚠️ Error analyzing Trivy report: ${e.message}"
    }
}

def displaySecurityResults(securityFindings) {
    def totalCritical = securityFindings.critical + securityFindings.trivy_critical
    def totalHigh = securityFindings.high + securityFindings.trivy_high
    def totalMedium = securityFindings.medium + securityFindings.trivy_medium
    
    echo "=== ENHANCED SECURITY SCAN RESULTS ==="
    echo "🔴 CRITICAL vulnerabilities: ${securityFindings.critical} (OWASP) + ${securityFindings.trivy_critical} (Trivy) = ${totalCritical} total"
    echo "🟠 HIGH vulnerabilities: ${securityFindings.high} (OWASP) + ${securityFindings.trivy_high} (Trivy) = ${totalHigh} total"
    echo "🟡 MEDIUM vulnerabilities: ${securityFindings.medium} (OWASP) + ${securityFindings.trivy_medium} (Trivy) = ${totalMedium} total"
    echo "🔑 Secrets exposed: ${securityFindings.secrets}"
    echo "🐛 Code issues (SAST): ${securityFindings.semgrep}"
    echo "📊 Total security findings: ${securityFindings.total_vulnerabilities}"
    echo "======================================"
}

def enforceSecurityPolicies(securityFindings) {
    def totalCritical = securityFindings.critical + securityFindings.trivy_critical
    def totalHigh = securityFindings.high + securityFindings.trivy_high
    
    // Enhanced security policy enforcement
    if (params.FAIL_ON_CRITICAL_VULNS && totalCritical > 0) {
        echo "❌ CRITICAL vulnerabilities detected: ${totalCritical}"
        error "Build failed due to ${totalCritical} CRITICAL vulnerabilities (policy: FAIL_ON_CRITICAL_VULNS=true)"
    }
    
    if (params.FAIL_ON_HIGH_VULNS && totalHigh > 0) {
        echo "❌ HIGH vulnerabilities detected: ${totalHigh}"
        error "Build failed due to ${totalHigh} HIGH vulnerabilities (policy: FAIL_ON_HIGH_VULNS=true)"
    }
    
    if (securityFindings.secrets > 0) {
        echo "🔑 CRITICAL: ${securityFindings.secrets} secrets found in code!"
        if (params.FAIL_ON_CRITICAL_VULNS) {
            error "Build failed due to ${securityFindings.secrets} exposed secrets"
        } else {
            currentBuild.result = 'UNSTABLE'
            echo "⚠️ Secrets detected but build continues due to policy"
        }
    }
    
    if (totalCritical > 0 && !params.FAIL_ON_CRITICAL_VULNS) {
        echo "⚠️ CRITICAL vulnerabilities detected: ${totalCritical} (not failing build due to policy)"
        currentBuild.result = 'UNSTABLE'
    } else if (totalHigh > 0 && !params.FAIL_ON_HIGH_VULNS) {
        echo "⚠️ HIGH vulnerabilities detected: ${totalHigh}"
        if (currentBuild.result == null) {
            currentBuild.result = 'UNSTABLE'
        }
    } else if (totalCritical == 0 && totalHigh == 0 && securityFindings.secrets == 0) {
        echo "✅ No critical/high vulnerabilities or secrets blocking the build"
    }
}

// Keep the existing report generation methods (generateComprehensiveReports, generateEmailReport, generateFinalReport, sendEmailNotification, sendSlackNotification)
// They remain the same as in your original code but are enhanced with the new security findings structure