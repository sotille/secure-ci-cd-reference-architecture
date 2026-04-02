# Secure CI/CD Implementation Guide

## Table of Contents

- [GitHub Actions Implementation](#github-actions-implementation)
- [GitLab CI Implementation](#gitlab-ci-implementation)
- [Jenkins Implementation](#jenkins-implementation)
- [Security Gate Configuration](#security-gate-configuration)
- [Break-the-Build Criteria](#break-the-build-criteria)
- [Pipeline as Code Security](#pipeline-as-code-security)
- [Runner and Agent Hardening](#runner-and-agent-hardening)
- [Dependency Pinning Strategies](#dependency-pinning-strategies)
- [SBOM Generation in Pipeline](#sbom-generation-in-pipeline)

---

## GitHub Actions Implementation

### Repository Security Configuration

Before implementing pipeline security controls, configure the repository security baseline:

**Repository settings (via GitHub API or Terraform):**
```hcl
# Terraform: GitHub repository security settings
resource "github_repository" "app" {
  name        = "myapp"
  visibility  = "private"

  security_and_analysis {
    advanced_security {
      status = "enabled"
    }
    secret_scanning {
      status = "enabled"
    }
    secret_scanning_push_protection {
      status = "enabled"
    }
  }
}

# Branch protection
resource "github_branch_protection" "main" {
  repository_id = github_repository.app.node_id
  pattern       = "main"

  required_status_checks {
    strict   = true
    contexts = [
      "security-scan / sast",
      "security-scan / sca",
      "security-scan / secrets",
      "security-scan / container-scan"
    ]
  }

  required_pull_request_reviews {
    dismiss_stale_reviews           = true
    require_code_owner_reviews      = true
    required_approving_review_count = 2
    require_last_push_approval      = true
  }

  restrict_pushes {
    push_allowances = []
  }

  require_signed_commits       = true
  require_conversation_resolution = true
  allows_force_pushes          = false
  allows_deletions             = false
}
```

### Complete Secure Pipeline: GitHub Actions

```yaml
# .github/workflows/secure-pipeline.yml
name: Secure CI Pipeline

on:
  pull_request:
    branches: [main, 'release/**']
  push:
    branches: [main]

# Least-privilege permissions at workflow level
permissions:
  contents: read

env:
  REGISTRY: ghcr.io
  IMAGE_NAME: ${{ github.repository }}

jobs:
  # ============================================================
  # SECRET DETECTION
  # ============================================================
  secrets-scan:
    name: Secrets Detection
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4 pinned to SHA
        with:
          fetch-depth: 0  # Full history for git log scanning

      - name: Run Gitleaks
        uses: gitleaks/gitleaks-action@a18c04b7c1a04db9f0d25fb31a745b3cdfc64ac9  # v2 pinned
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          GITLEAKS_LICENSE: ${{ secrets.GITLEAKS_LICENSE }}

  # ============================================================
  # STATIC ANALYSIS (SAST)
  # ============================================================
  sast:
    name: Static Analysis
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
        with:
          fetch-depth: 0

      - name: Run Semgrep SAST
        uses: semgrep/semgrep-action@713efdd345f3035192eaa63f56867b88e63e4e5d  # pinned
        with:
          config: >-
            p/owasp-top-ten
            p/secrets
            p/javascript
            p/python
          publishToken: ${{ secrets.SEMGREP_APP_TOKEN }}
          # Only report new findings on PRs (differential scan)
          generateSarif: '1'
        env:
          SEMGREP_RULES_URL: "https://semgrep.dev/c/p/owasp-top-ten"

      - name: Upload Semgrep SARIF
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: semgrep.sarif

  # ============================================================
  # SOFTWARE COMPOSITION ANALYSIS (SCA)
  # ============================================================
  sca:
    name: Dependency Scanning
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683

      - name: Run Snyk SCA
        uses: snyk/actions/node@806182742461562b67788a64410098c9d9b96adb  # pinned
        continue-on-error: false
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
        with:
          args: >-
            --severity-threshold=high
            --fail-on=all
            --sarif-file-output=snyk.sarif
            --org=${{ vars.SNYK_ORG_ID }}

      - name: Upload Snyk SARIF
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: snyk.sarif

  # ============================================================
  # BUILD AND CONTAINER SECURITY
  # ============================================================
  build-and-scan:
    name: Build and Container Scan
    runs-on: ubuntu-latest
    needs: [secrets-scan, sast, sca]  # Only build after security scans pass
    permissions:
      contents: read
      packages: write
      security-events: write
      id-token: write  # For OIDC signing
    outputs:
      image-digest: ${{ steps.build.outputs.digest }}
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3

      - name: Log in to Container Registry
        uses: docker/login-action@v3
        with:
          registry: ${{ env.REGISTRY }}
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Extract metadata for Docker
        id: meta
        uses: docker/metadata-action@v5
        with:
          images: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}
          tags: |
            type=sha,format=long
            type=ref,event=branch
            type=semver,pattern={{version}}

      - name: Build container image
        id: build
        uses: docker/build-push-action@v5
        with:
          context: .
          push: false  # Don't push until scanned
          load: true   # Load into local Docker for scanning
          tags: ${{ steps.meta.outputs.tags }}
          labels: ${{ steps.meta.outputs.labels }}
          cache-from: type=gha
          cache-to: type=gha,mode=max

      - name: Run Trivy container scan
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:sha-${{ github.sha }}
          format: sarif
          output: trivy-results.sarif
          severity: CRITICAL,HIGH
          exit-code: 1           # Fail on CRITICAL or HIGH
          ignore-unfixed: true
          vuln-type: os,library

      - name: Upload Trivy SARIF
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: trivy-results.sarif

      - name: Push container image (after scan passes)
        uses: docker/build-push-action@v5
        with:
          context: .
          push: true
          tags: ${{ steps.meta.outputs.tags }}
          labels: ${{ steps.meta.outputs.labels }}

  # ============================================================
  # ARTIFACT SIGNING
  # ============================================================
  sign:
    name: Sign Artifact
    runs-on: ubuntu-latest
    needs: build-and-scan
    if: github.ref == 'refs/heads/main'
    permissions:
      contents: read
      packages: write
      id-token: write  # Required for keyless Cosign signing
    steps:
      - name: Install Cosign
        uses: sigstore/cosign-installer@v3

      - name: Log in to Container Registry
        uses: docker/login-action@v3
        with:
          registry: ${{ env.REGISTRY }}
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Sign container image (keyless)
        run: |
          cosign sign --yes \
            --rekor-url=https://rekor.sigstore.dev \
            ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}@${{ needs.build-and-scan.outputs.image-digest }}

  # ============================================================
  # IaC SECURITY SCANNING
  # ============================================================
  iac-scan:
    name: IaC Security Scan
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683

      - name: Run Checkov IaC Scan
        uses: bridgecrewio/checkov-action@master
        with:
          directory: ./terraform
          framework: terraform,dockerfile,kubernetes
          soft_fail_on: MEDIUM,LOW,INFO
          hard_fail_on: HIGH,CRITICAL
          output_format: sarif
          output_file_path: checkov.sarif

      - name: Upload Checkov SARIF
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: checkov.sarif
```

### OIDC Cloud Authentication

```yaml
# .github/workflows/deploy.yml
jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      id-token: write  # Required for OIDC
      contents: read
    environment: production  # Requires environment protection rules
    steps:
      # AWS OIDC
      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ vars.AWS_PROD_DEPLOY_ROLE_ARN }}
          aws-region: ${{ vars.AWS_REGION }}
          # The IAM role trust policy must restrict to this repo and ref:
          # Condition: StringEquals
          #   token.actions.githubusercontent.com:sub:
          #     repo:myorg/myrepo:ref:refs/heads/main

      # GCP Workload Identity Federation
      - name: Authenticate to GCP
        uses: google-github-actions/auth@v2
        with:
          workload_identity_provider: ${{ vars.GCP_WORKLOAD_IDENTITY_PROVIDER }}
          service_account: ${{ vars.GCP_SERVICE_ACCOUNT }}
```

---

## GitLab CI Implementation

### GitLab Security Scanning Configuration

GitLab provides built-in security scanning through its Ultimate tier. For other tiers, integrate open-source tools directly.

**Complete `.gitlab-ci.yml`:**
```yaml
# .gitlab-ci.yml
stages:
  - security-scan
  - build
  - test
  - scan-artifacts
  - sign
  - deploy

variables:
  # Pin Docker image versions for reproducibility
  TRIVY_VERSION: "0.49.0"
  CHECKOV_VERSION: "3.2.0"
  COSIGN_VERSION: "2.2.3"
  DOCKER_DRIVER: overlay2
  DOCKER_TLS_CERTDIR: "/certs"
  # Registry
  IMAGE_TAG: $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA

# ============================================================
# SECRET DETECTION
# ============================================================
gitleaks:
  stage: security-scan
  image:
    name: zricethezav/gitleaks:v8.18.4
    entrypoint: [""]
  script:
    - gitleaks detect
        --source="$CI_PROJECT_DIR"
        --verbose
        --redact
        --report-format=sarif
        --report-path=gitleaks-report.sarif
  artifacts:
    when: always
    paths:
      - gitleaks-report.sarif
    expire_in: 30 days
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH

# ============================================================
# SAST
# ============================================================
semgrep-sast:
  stage: security-scan
  image: semgrep/semgrep:1.64.0
  script:
    - semgrep ci
        --config=p/owasp-top-ten
        --config=p/secrets
        --sarif
        --output=semgrep-report.sarif
        --severity=ERROR
        --error  # Exit non-zero on findings above threshold
  variables:
    SEMGREP_APP_TOKEN: $SEMGREP_APP_TOKEN
  artifacts:
    when: always
    reports:
      sast: semgrep-report.sarif
    paths:
      - semgrep-report.sarif
    expire_in: 30 days

# ============================================================
# SCA
# ============================================================
dependency-scan:
  stage: security-scan
  image: snyk/snyk:node
  script:
    - snyk auth $SNYK_TOKEN
    - snyk test
        --severity-threshold=high
        --fail-on=all
        --sarif-file-output=snyk-report.sarif
  artifacts:
    when: always
    paths:
      - snyk-report.sarif
    expire_in: 30 days

# ============================================================
# BUILD
# ============================================================
docker-build:
  stage: build
  image: docker:24.0.7
  services:
    - docker:24.0.7-dind
  needs:
    - gitleaks
    - semgrep-sast
    - dependency-scan
  before_script:
    - echo $CI_REGISTRY_PASSWORD | docker login -u $CI_REGISTRY_USER --password-stdin $CI_REGISTRY
  script:
    - docker build --tag $IMAGE_TAG .
    - docker push $IMAGE_TAG

# ============================================================
# CONTAINER SCANNING
# ============================================================
trivy-scan:
  stage: scan-artifacts
  image:
    name: aquasec/trivy:$TRIVY_VERSION
    entrypoint: [""]
  needs: [docker-build]
  before_script:
    - echo $CI_REGISTRY_PASSWORD | docker login -u $CI_REGISTRY_USER --password-stdin $CI_REGISTRY
  script:
    - trivy image
        --exit-code 1
        --severity CRITICAL,HIGH
        --ignore-unfixed
        --format sarif
        --output trivy-report.sarif
        $IMAGE_TAG
  artifacts:
    when: always
    paths:
      - trivy-report.sarif
    expire_in: 30 days

# ============================================================
# IaC SCANNING
# ============================================================
checkov-iac:
  stage: security-scan
  image:
    name: bridgecrew/checkov:$CHECKOV_VERSION
    entrypoint: [""]
  script:
    - checkov
        -d .
        --framework terraform,dockerfile,kubernetes
        --soft-fail-on MEDIUM,LOW,INFO
        --hard-fail-on HIGH,CRITICAL
        --output sarif
        --output-file-path checkov-report.sarif
  artifacts:
    when: always
    paths:
      - checkov-report.sarif
    expire_in: 30 days

# ============================================================
# ARTIFACT SIGNING (main branch only)
# ============================================================
cosign-sign:
  stage: sign
  image:
    name: bitnami/cosign:$COSIGN_VERSION
    entrypoint: [""]
  needs: [trivy-scan]
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
  script:
    - echo $CI_REGISTRY_PASSWORD | cosign login --username $CI_REGISTRY_USER --password-stdin $CI_REGISTRY
    - cosign sign --yes
        --rekor-url=https://rekor.sigstore.dev
        $IMAGE_TAG

# ============================================================
# DEPLOYMENT (production — manual trigger required)
# ============================================================
deploy-production:
  stage: deploy
  needs: [cosign-sign]
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
      when: manual  # Require human approval for production
  environment:
    name: production
    url: https://myapp.example.com
  script:
    - kubectl set image deployment/myapp app=$IMAGE_TAG --namespace=production
```

### GitLab OIDC with Cloud Providers

```yaml
deploy-aws:
  stage: deploy
  image: amazon/aws-cli:2.15.0
  id_tokens:
    AWS_OIDC_TOKEN:
      aud: https://gitlab.com
  script:
    - |
      export AWS_WEB_IDENTITY_TOKEN_FILE=/tmp/aws-token
      echo $AWS_WEB_IDENTITY_TOKEN > $AWS_WEB_IDENTITY_TOKEN_FILE
      aws sts assume-role-with-web-identity \
        --role-arn $AWS_PROD_DEPLOY_ROLE_ARN \
        --role-session-name "gitlab-$CI_JOB_ID" \
        --web-identity-token file://$AWS_WEB_IDENTITY_TOKEN_FILE \
        --query 'Credentials' \
        --output json > /tmp/credentials
      export AWS_ACCESS_KEY_ID=$(jq -r '.AccessKeyId' /tmp/credentials)
      export AWS_SECRET_ACCESS_KEY=$(jq -r '.SecretAccessKey' /tmp/credentials)
      export AWS_SESSION_TOKEN=$(jq -r '.SessionToken' /tmp/credentials)
      # Now use AWS CLI with temporary credentials
      aws ecs update-service --cluster production --service myapp --force-new-deployment
```

---

## Jenkins Implementation

### Jenkins Declarative Pipeline

```groovy
// Jenkinsfile
pipeline {
    agent {
        // Use ephemeral Kubernetes pod agent
        kubernetes {
            yaml '''
apiVersion: v1
kind: Pod
spec:
  serviceAccountName: jenkins-agent
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 1000
  containers:
    - name: build
      image: eclipse-temurin:21-jdk-alpine@sha256:<pinned-digest>
      command: [cat]
      tty: true
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: false
        capabilities:
          drop: [ALL]
      resources:
        limits:
          cpu: "2"
          memory: "4Gi"
        requests:
          cpu: "500m"
          memory: "1Gi"
    - name: docker
      image: docker:24.0.7-dind@sha256:<pinned-digest>
      securityContext:
        privileged: false  # Use rootless Docker or Kaniko instead
      tty: true
    - name: trivy
      image: aquasec/trivy:0.49.0@sha256:<pinned-digest>
      command: [cat]
      tty: true
'''
        }
    }

    options {
        timeout(time: 30, unit: 'MINUTES')
        disableConcurrentBuilds()
        buildDiscarder(logRotator(numToKeepStr: '50'))
    }

    environment {
        REGISTRY = 'registry.mycompany.com'
        IMAGE_NAME = 'myapp'
        IMAGE_TAG = "${REGISTRY}/${IMAGE_NAME}:${GIT_COMMIT}"
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Security Scan') {
            parallel {
                stage('Secrets Detection') {
                    steps {
                        container('build') {
                            sh '''
                                # Install Gitleaks
                                wget -qO /usr/local/bin/gitleaks \
                                    https://github.com/gitleaks/gitleaks/releases/download/v8.18.4/gitleaks_8.18.4_linux_x64
                                chmod +x /usr/local/bin/gitleaks
                                gitleaks detect --source=. --verbose --redact \
                                    --report-format=sarif --report-path=gitleaks.sarif || \
                                    (echo "SECRETS DETECTED - blocking build"; exit 1)
                            '''
                        }
                    }
                }

                stage('SAST') {
                    steps {
                        container('build') {
                            sh '''
                                # Run Semgrep
                                pip install semgrep
                                semgrep ci \
                                    --config=p/owasp-top-ten \
                                    --config=p/java \
                                    --sarif \
                                    --output=semgrep.sarif \
                                    --error \
                                    --severity=ERROR
                            '''
                        }
                    }
                }

                stage('SCA') {
                    steps {
                        container('build') {
                            withCredentials([string(credentialsId: 'snyk-token', variable: 'SNYK_TOKEN')]) {
                                sh '''
                                    npm install -g snyk
                                    snyk auth $SNYK_TOKEN
                                    snyk test \
                                        --severity-threshold=high \
                                        --fail-on=all \
                                        --sarif-file-output=snyk.sarif
                                '''
                            }
                        }
                    }
                }
            }
        }

        stage('Build') {
            steps {
                container('docker') {
                    sh "docker build -t ${IMAGE_TAG} ."
                }
            }
        }

        stage('Container Scan') {
            steps {
                container('trivy') {
                    sh """
                        trivy image \
                            --exit-code 1 \
                            --severity CRITICAL,HIGH \
                            --ignore-unfixed \
                            --format sarif \
                            --output trivy.sarif \
                            ${IMAGE_TAG}
                    """
                }
            }
        }

        stage('Push and Sign') {
            when {
                branch 'main'
            }
            steps {
                container('docker') {
                    withCredentials([usernamePassword(
                        credentialsId: 'registry-credentials',
                        usernameVariable: 'REGISTRY_USER',
                        passwordVariable: 'REGISTRY_PASSWORD'
                    )]) {
                        sh """
                            echo $REGISTRY_PASSWORD | docker login -u $REGISTRY_USER --password-stdin ${REGISTRY}
                            docker push ${IMAGE_TAG}
                        """
                    }
                }
                container('build') {
                    sh """
                        # Install cosign
                        wget -qO /usr/local/bin/cosign \
                            https://github.com/sigstore/cosign/releases/download/v2.2.3/cosign-linux-amd64
                        chmod +x /usr/local/bin/cosign
                        # Sign with key stored in Jenkins credentials
                        cosign sign --key k8s://jenkins/cosign-key ${IMAGE_TAG}
                    """
                }
            }
        }

        stage('Deploy to Production') {
            when {
                branch 'main'
            }
            input {
                message "Deploy to production?"
                ok "Deploy"
                submitter "release-engineers"
            }
            steps {
                container('build') {
                    withKubeConfig([credentialsId: 'production-kubeconfig']) {
                        sh "kubectl set image deployment/myapp app=${IMAGE_TAG} -n production"
                    }
                }
            }
        }
    }

    post {
        always {
            // Publish security reports
            recordIssues tools: [sarif(pattern: '*.sarif')]
        }
        failure {
            // Notify security team on gate failures
            emailext(
                subject: "Security Gate Failure: ${JOB_NAME} #${BUILD_NUMBER}",
                body: "Security gates failed in pipeline ${JOB_NAME}. See: ${BUILD_URL}",
                to: 'security-team@mycompany.com'
            )
        }
    }
}
```

---

## Security Gate Configuration

### Gate Threshold Policy Reference

```yaml
# security-policy.yaml (stored in a policy repository, consumed by all pipelines)
version: "1.0"
gates:
  secrets:
    policy: zero-tolerance
    blocking: true
    override: false

  sast:
    critical:
      blocking: true
      override_requires: security_engineer
      override_max_days: 7
    high:
      blocking: true
      override_requires: security_champion
      override_max_days: 14
    medium:
      blocking: false
      track: true
      sla_days: 30
    low:
      blocking: false
      track: false

  sca:
    critical:
      blocking: true
      with_fix:
        action: require_upgrade
      without_fix:
        action: require_exception
        exception_requires: security_engineer
        exception_max_days: 30
    high:
      blocking: true
      override_requires: security_champion
      override_max_days: 7

  container_scan:
    critical:
      blocking: true
      with_fix: require_base_image_update
      without_fix: require_security_engineer_exception
    high:
      blocking: true
      override_max_days: 7

  iac_scan:
    critical:
      blocking: true
    high:
      blocking: true
      override_max_days: 14
```

---

## Break-the-Build Criteria

The following conditions must cause an immediate pipeline failure and block progression:

### Absolute Blocks (No Override)

These conditions indicate that continuing the pipeline would introduce unacceptable risk. There is no override path — the issue must be fixed before any build progress is allowed.

1. **Any secret detected in source code or build artifacts**
   - API keys, private keys, passwords, tokens, certificates
   - Does not matter if the repository is private
   - Even test/dummy secrets must not be committed

2. **Critical CVE with a known working exploit in a production dependency**
   - CISA KEV (Known Exploited Vulnerabilities) catalog entries
   - EPSS score > 0.9 combined with CVSS >= 9.0

3. **Build system or pipeline configuration tampering detected**
   - Unexpected changes to core pipeline configuration files
   - Workflow files modified without appropriate review

### Standard Break-the-Build (Override Allowed with Process)

1. **SAST Critical finding** — override requires Security Engineer approval + remediation plan within 7 days
2. **SAST High finding** — override requires Security Champion approval + remediation plan within 14 days
3. **SCA Critical CVE** — upgrade must be applied; if no upgrade exists, requires Security Engineer exception
4. **SCA High CVE** — upgrade required within 7 days; exception requires Security Champion
5. **Container image Critical CVE** — base image update required; exception requires Security Engineer
6. **IaC Critical/High misconfiguration** — must be fixed before promotion to staging

### Progressive Enforcement (New Findings Only)

For repositories migrating from legacy codebases, a "new findings only" mode can be configured for SAST and SCA to prevent pre-existing findings from blocking development while new findings are blocked:

```yaml
# GitHub Actions: Semgrep differential scan
- name: Semgrep (new findings only)
  uses: semgrep/semgrep-action@v1
  with:
    config: p/owasp-top-ten
    # Only report findings introduced in this PR vs. the base branch
  env:
    SEMGREP_BASELINE_REF: ${{ github.base_ref }}
```

---

## Pipeline as Code Security

### Securing GitHub Actions Workflows

**Pin all actions to commit SHA:**
```yaml
# INSECURE: tags are mutable and can be changed by the action maintainer
- uses: actions/checkout@v4

# SECURE: commit SHA is immutable
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
```

**Use minimal permissions:**
```yaml
# Declare minimal permissions at workflow level
permissions:
  contents: read  # Default: read access to repository contents only

jobs:
  build:
    # Override at job level if specific permissions needed
    permissions:
      contents: read
      packages: write      # Only if this job pushes to registry
      security-events: write  # Only if this job uploads SARIF
      id-token: write      # Only if this job uses OIDC
```

**Prevent injection from untrusted inputs:**
```yaml
# INSECURE: PR title directly interpolated into shell
- run: echo "Building PR: ${{ github.event.pull_request.title }}"

# SECURE: Assign to environment variable; shell handles safely
- run: echo "Building PR: $PR_TITLE"
  env:
    PR_TITLE: ${{ github.event.pull_request.title }}
```

**Restrict workflow triggers from forks:**
```yaml
# Prevent secrets from being exposed to fork-based PRs
on:
  pull_request_target:  # Use pull_request, not pull_request_target (unless you understand the risk)
    types: [opened, synchronize]

# If you must use pull_request_target, require approval for fork PRs:
jobs:
  build:
    environment:
      ${{ github.event.pull_request.head.repo.fork && 'fork-review-required' || 'internal' }}
```

---

## Runner and Agent Hardening

### GitHub Actions Self-Hosted Runner Hardening

```bash
# 1. Run runner as a dedicated non-root user
useradd -m -s /bin/bash github-runner
# Never run as root

# 2. Use --ephemeral flag to ensure runner handles only one job
./config.sh --url https://github.com/myorg --token TOKEN --ephemeral

# 3. Network egress restrictions (iptables)
# Allow only required outbound connections
iptables -A OUTPUT -d api.github.com -j ACCEPT
iptables -A OUTPUT -d *.pkg.github.com -j ACCEPT
iptables -A OUTPUT -d registry.npmjs.org -j ACCEPT
iptables -A OUTPUT -d pypi.org -j ACCEPT
# Block all other outbound
iptables -A OUTPUT -j DROP

# 4. Mount /tmp as tmpfs (in-memory, no disk persistence)
mount -t tmpfs -o size=2g tmpfs /tmp
```

**Kubernetes-based ephemeral runners (GitHub Actions Runner Controller):**
```yaml
apiVersion: actions.summerwind.dev/v1alpha1
kind: RunnerDeployment
metadata:
  name: myapp-runners
spec:
  replicas: 3
  template:
    spec:
      repository: myorg/myrepo
      ephemeral: true  # Runner deregisters after each job
      image: summerwind/actions-runner:ubuntu-22.04
      imagePullPolicy: IfNotPresent
      resources:
        limits:
          cpu: "2"
          memory: "4Gi"
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
      env:
        - name: RUNNER_WORKDIR
          value: /tmp/runner/work  # Work in tmpfs
      volumeMounts:
        - name: work
          mountPath: /tmp/runner/work
      volumes:
        - name: work
          emptyDir:
            medium: Memory  # In-memory work directory
            sizeLimit: 2Gi
```

### Jenkins Agent Hardening

```yaml
# Kubernetes Jenkins agent pod template with security hardening
apiVersion: v1
kind: Pod
spec:
  serviceAccountName: jenkins-agent
  # Prevent privilege escalation and enforce read-only filesystem
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 1000
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: jnlp
      image: jenkins/inbound-agent:3107.v665000b_51092-15@sha256:<digest>
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: false
        capabilities:
          drop: [ALL]
      resources:
        limits:
          cpu: "2"
          memory: "4Gi"
        requests:
          cpu: "500m"
          memory: "1Gi"
  # Prevent DNS exfiltration attacks via dnsConfig
  dnsConfig:
    nameservers:
      - 10.0.0.10  # Internal DNS only
    searches:
      - cluster.local
  automountServiceAccountToken: false  # Don't mount K8s service account token
```

---

## Dependency Pinning Strategies

### Language-Specific Pinning

**Node.js:**
```bash
# Generate lock file
npm install
# Always commit package-lock.json
git add package-lock.json

# Use npm ci (not npm install) in CI — uses lock file exactly
npm ci  # Faster, reproducible, fails if lock file is out of sync
```

**Python:**
```bash
# Use pip-compile to generate pinned requirements
pip install pip-tools
pip-compile requirements.in --generate-hashes  # Include hashes for integrity

# requirements.txt (compiled, pinned with hashes):
# requests==2.31.0 \
#     --hash=sha256:942c5a758f98d790eaed1a29cb6eefc7896... \
#     --hash=sha256:58cd2187423839... \

# Install in CI:
pip install -r requirements.txt --require-hashes
```

**Docker base images:**
```dockerfile
# Get the digest: docker inspect --format='{{index .RepoDigests 0}}' python:3.12-slim
# Or: crane digest python:3.12-slim

# Pin by digest (immutable):
FROM python:3.12.2-slim@sha256:12b3aac34a75b79658b30c071a7db1a7c434a14c63abf40da6fce6b65dfb98fb

# Renovate or Dependabot can automatically update pinned digests when new versions are released
```

**GitHub Actions:**
```python
# Use a tool like tj-actions/verify-changed-files or pin-github-action to pin actions
# Automate with Renovate:

# renovate.json
{
  "extends": ["config:base"],
  "github-actions": {
    "enabled": true,
    "pinDigests": true  # Automatically pin GitHub Actions to commit SHA
  }
}
```

---

## SBOM Generation in Pipeline

### Syft SBOM Generation

Syft generates SBOMs in SPDX, CycloneDX, and other formats from container images, file systems, and directories.

**GitHub Actions:**
```yaml
- name: Generate SBOM with Syft
  uses: anchore/sbom-action@v0
  with:
    image: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }}
    format: spdx-json
    output-file: sbom.spdx.json
    artifact-name: sbom-${{ github.sha }}.spdx.json

- name: Generate CycloneDX SBOM
  uses: anchore/sbom-action@v0
  with:
    image: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }}
    format: cyclonedx-json
    output-file: sbom.cyclonedx.json
    artifact-name: sbom-${{ github.sha }}.cyclonedx.json

# Attach SBOM as attestation to the image
- name: Attest SBOM
  uses: actions/attest-sbom@v1
  with:
    subject-name: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}
    subject-digest: ${{ steps.build.outputs.digest }}
    sbom-path: sbom.spdx.json
    push-to-registry: true
```

**CycloneDX for language packages:**
```bash
# Node.js
npx @cyclonedx/cyclonedx-npm --output-file sbom-node.cyclonedx.json

# Python
pip install cyclonedx-bom
cyclonedx-py environment --output-format json --output-file sbom-python.cyclonedx.json

# Java (Maven)
mvn org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom
# Produces: target/bom.json and target/bom.xml

# Go
go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@v1
cyclonedx-gomod app -output sbom-go.cyclonedx.json
```

### SBOM Storage and Querying

```bash
# Store SBOM in artifact registry alongside container image
cosign attach sbom \
  --sbom sbom.spdx.json \
  --type spdx \
  ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}@${{ steps.build.outputs.digest }}

# Query SBOM for vulnerable component
# (useful when a new CVE is disclosed and you need to know which images are affected)
grype sbom:sbom.spdx.json --output json | \
  jq '.matches[] | select(.vulnerability.severity == "Critical") | .artifact.name'

# OSV Scanner: scan SBOM against OSV vulnerability database
osv-scanner --sbom sbom.spdx.json
```
