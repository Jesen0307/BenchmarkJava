pipeline {
    agent any

    environment {
        REPORTS_DIR = 'security-reports'
        // Jenkins container is attached to the SonarQube 'sonarnet' network,
        // so SonarQube is reachable by its Docker DNS name (stable, no hardcoded IP).
        SONAR_HOST_URL = 'http://sonarqube:9000'
        PATH = "/opt/sonar-scanner/bin:${env.PATH}"
        SONAR_TOKEN = 'squ_a76c5e818a392cb07370af0fb874c9e3fe84ec90'
        SONAR_PROJECT_KEY = 'BenchmarkJava'
    }

    stages {
        stage('Install Dependencies') {
            steps {
                sh '''
                    sudo apt-get update
                    sudo apt-get install -y python3 python3-pip python3-venv curl unzip docker.io default-jdk

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
                sh 'chmod +x gradlew'
                sh './gradlew classes printRuntimeClasspath --no-daemon'
            }
        }

        stage('Security Analysis') {
            steps {
                script {
                    sh 'mkdir -p $REPORTS_DIR'

                    parallel (
                        'Semgrep SAST': {
                            sh 'chmod +x scripts/semgrep-scan.sh'
                            sh './scripts/semgrep-scan.sh . $REPORTS_DIR'
                        },
                        'SonarQube Analysis': {
                            sh 'chmod +x scripts/sonarqube-scan.sh'
                            sh './scripts/sonarqube-scan.sh . $SONAR_PROJECT_KEY $SONAR_HOST_URL $SONAR_TOKEN $REPORTS_DIR'
                        }
                    )
                }
            }
        }

        stage('Deduplicate Findings') {
            steps {
                sh 'python3 scripts/security_processor.py --workspace $REPORTS_DIR'
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
