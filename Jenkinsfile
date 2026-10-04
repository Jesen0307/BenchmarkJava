pipeline {
    agent any

    environment {
        REPORTS_DIR = 'security-reports'
        // Jenkins container is attached to the SonarQube 'sonarnet' network,
        // so SonarQube is reachable by its Docker DNS name (stable, no hardcoded IP).
        SONAR_HOST_URL = 'http://sonarqube:9000'
        PATH = "/opt/sonar-scanner/bin:${env.PATH}"
        SONAR_TOKEN = credentials('sonar-token')
        SONAR_PROJECT_KEY = 'BenchmarkJava'
    }

    stages {
        stage('Install Dependencies') {
            steps {
                sh '''
                    sudo apt-get update
                    sudo apt-get install -y python3 python3-pip python3-venv curl unzip docker.io default-jdk maven

                    if [ ! -d "/usr/lib/jvm/java-17-temurin" ]; then
                        sudo mkdir -p /usr/lib/jvm/java-17-temurin
                        curl -sL "https://api.adoptium.net/v3/binary/latest/17/ga/linux/x64/jdk/hotspot/normal/eclipse" | sudo tar -xz -C /usr/lib/jvm/java-17-temurin --strip-components=1
                    fi

                    sudo pip3 install semgrep --break-system-packages || sudo pip3 install semgrep

                    # SonarScanner CLI (pinned version; installed once on the agent)
                    SONAR_SCANNER_VERSION=8.1.0.6389
                    if [ ! -x /opt/sonar-scanner/bin/sonar-scanner ]; then
                        sudo mkdir -p /opt/sonar-scanner
                        curl -fsSL "https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-${SONAR_SCANNER_VERSION}-linux-x64.zip" -o /tmp/sonar-scanner.zip
                        sudo unzip -q /tmp/sonar-scanner.zip -d /tmp/sonar-scanner-install
                        sudo cp -r /tmp/sonar-scanner-install/sonar-scanner-*/. /opt/sonar-scanner/
                        sudo chmod -R +x /opt/sonar-scanner/bin /opt/sonar-scanner/jre/bin
                        rm -rf /tmp/sonar-scanner.zip /tmp/sonar-scanner-install
                    fi
                '''
            }
        }

        stage('Build (Compile Java)') {
            steps {
                sh 'git fetch --unshallow || true; git fetch origin master:refs/remotes/origin/master || true'
                sh 'mvn -B -DskipTests -Dspotless.apply.skip=true -Dspotless.check.skip=true compile --no-transfer-progress'
                sh 'mkdir -p build && mvn -B -Dspotless.apply.skip=true -Dspotless.check.skip=true dependency:build-classpath -Dmdep.outputFile=build/runtimeClasspath.txt --no-transfer-progress'
            }
        }

        stage('Security Analysis') {
            steps {
                script {
                    sh 'mkdir -p $REPORTS_DIR'
                    
                    def semgrepFailed = false

                    parallel (
                        'Semgrep SAST': {
                            sh 'chmod +x scripts/semgrep-scan.sh'
                            def semgrepExitCode = sh(
                                script: './scripts/semgrep-scan.sh . $REPORTS_DIR',
                                returnStatus: true
                            )
                            if (semgrepExitCode != 0) {
                                semgrepFailed = true
                            }
                        },
                        'SonarQube Analysis': {
                            sh 'chmod +x scripts/sonarqube-scan.sh'
                            sh './scripts/sonarqube-scan.sh . $SONAR_PROJECT_KEY $SONAR_HOST_URL $SONAR_TOKEN $REPORTS_DIR'
                        }
                    )

                    if (semgrepFailed) {
                        env.SEMGREP_FAILED = 'true'
                        echo "Semgrep found blocking vulnerabilities."
                    } else {
                        env.SEMGREP_FAILED = 'false'
                    }
                }
            }
        }

        stage('Deduplicate Findings') {
            steps {
                script {
                    def sonarFailed = false

                    def qgExitCode = sh(
                        script: '''
                            TIMEOUT=600
                            ELAPSED=0
                            INTERVAL=10
                            STATUS="PENDING"

                            while [ $ELAPSED -lt $TIMEOUT ]; do
                                RESPONSE=$(curl -s -u "${SONAR_TOKEN}:" "${SONAR_HOST_URL}/api/qualitygates/project_status?projectKey=${SONAR_PROJECT_KEY}")
                                STATUS=$(echo "$RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin).get('projectStatus', {}).get('status', 'PENDING'))" 2>/dev/null || echo "PENDING")

                                if [ "$STATUS" = "OK" ] || [ "$STATUS" = "ERROR" ] || [ "$STATUS" = "WARN" ]; then
                                    echo "SonarQube Quality Gate status: $STATUS"
                                    break
                                fi

                                echo "Quality Gate status is $STATUS. Waiting for analysis computation..."
                                sleep $INTERVAL
                                ELAPSED=$((ELAPSED + INTERVAL))
                            done

                            if [ "$STATUS" != "OK" ]; then
                                exit 1
                            fi
                        ''',
                        returnStatus: true
                    )

                    if (qgExitCode != 0) {
                        sonarFailed = true
                        echo "SonarQube Quality Gate failed or timed out."
                    } else {
                        echo "SonarQube Quality Gate passed successfully."
                    }

                    sh 'python3 scripts/security_processor.py --workspace $REPORTS_DIR'

                    if (env.SEMGREP_FAILED == 'true' || sonarFailed) {
                        error("Pipeline failed due to security vulnerabilities or Quality Gate violations.")
                    }
                }
            }
        }
    }

    post {
        always {
            echo 'Pipeline execution completed.'
            archiveArtifacts artifacts: "${env.REPORTS_DIR}/*.json, ${env.REPORTS_DIR}/*.log", allowEmptyArchive: true
        }
    }
}
