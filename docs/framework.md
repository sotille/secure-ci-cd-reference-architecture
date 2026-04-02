# Security Controls Framework for CI/CD

## Table of Contents

- [Framework Overview](#framework-overview)
- [SAST Integration](#sast-integration)
- [DAST Integration](#dast-integration)
- [SCA and Dependency Scanning](#sca-and-dependency-scanning)
- [Secrets Detection and Management in Pipelines](#secrets-detection-and-management-in-pipelines)
- [Container Image Scanning](#container-image-scanning)
- [Artifact Signing and Verification](#artifact-signing-and-verification)
- [Deployment Strategies](#deployment-strategies)
- [Audit Logging Requirements](#audit-logging-requirements)
- [Compliance Considerations](#compliance-considerations)

---

## Framework Overview

The Secure CI/CD Controls Framework defines the security controls, tools, configuration requirements, and policies that govern the software delivery pipeline. It is organized around the pipeline stages where controls are applied, and provides specific tool configurations, threshold policies, and compliance mappings for each control category.

The framework follows a risk-based approach: controls are applied proportionally to the risk of each pipeline stage, with higher-trust stages (production) requiring more stringent validation than lower-trust stages (development).

### Controls Coverage Matrix

| Control Category | Pre-commit | CI Build | Staging | Production Deploy | Runtime |
|---|---|---|---|---|---|
| SAST | Optional | Required | N/A | N/A | N/A |
| DAST | N/A | N/A | Required | N/A | Optional |
| SCA | Optional | Required | Required | Gate | N/A |
| Secrets Detection | Required | Required | N/A | N/A | N/A |
| Container Scanning | N/A | Required | Required | Gate | Optional |
| Artifact Signing | N/A | Required | Verify | Required | N/A |
| IaC Scanning | Optional | Required | N/A | Gate | N/A |
| Compliance Validation | N/A | Optional | Required | Gate | Continuous |
| Audit Logging | N/A | Required | Required | Required | Required |

---

## SAST Integration

Static Application Security Testing (SAST) analyzes application source code without execution to identify security vulnerabilities at the earliest possible stage of the pipeline.

### Tool Selection Criteria

Evaluate SAST tools against these criteria:

| Criterion | Weight | Description |
|---|---|---|
| Language coverage | High | Must cover all languages in the organization's technology stack |
| Accuracy (false positive rate) | High | Target: < 15% false positive rate; high FP rates cause alert fatigue |
| CI/CD integration | High | Native GitHub Actions / GitLab CI / Jenkins integration; SARIF output support |
| Speed | High | Must complete within pipeline time budget (target: < 10 minutes for incremental scan) |
| Customization | Medium | Ability to write custom rules for organization-specific vulnerability patterns |
| IDE integration | Medium | Plugin availability for VSCode, IntelliJ for shift-left feedback |
| Compliance mappings | Medium | Built-in mapping to OWASP Top 10, CWE Top 25, NIST, PCI-DSS |
| Vulnerability DB currency | High | Vulnerability rules updated at least weekly |

### Recommended SAST Tools by Language

| Language | Open Source | Commercial |
|---|---|---|
| Python | Semgrep, Bandit, CodeQL | Checkmarx, Veracode |
| JavaScript / TypeScript | Semgrep, ESLint Security, CodeQL | Checkmarx, Veracode |
| Java | SpotBugs + FindSecBugs, CodeQL, Semgrep | Fortify, Checkmarx |
| Go | Semgrep, gosec, CodeQL | Snyk Code |
| C/C++ | Semgrep, FlawFinder, CodeQL | Fortify, Klocwork |
| C# / .NET | Semgrep, CodeQL, Security Code Scan | Fortify, Checkmarx |
| Ruby | Brakeman, Semgrep | Veracode |
| PHP | PHPCS Security Audit, Semgrep | Fortify |

### SAST Configuration and Thresholds

**Break-the-build policy:**

| Severity | Default Policy | Override Process |
|---|---|---|
| Critical | Block merge / block build | Requires Security Engineer sign-off; exception recorded in vulnerability tracker |
| High | Block merge | Security Champion can approve temporary exception with remediation plan within 7 days |
| Medium | Warning; non-blocking | Tracked in vulnerability management system; must be addressed within 30 days |
| Low | Informational | No mandatory action; reviewed in quarterly security debt sessions |

**Semgrep CI configuration:**
```yaml
# .semgrep.yml - organization SAST policy
rules:
  - id: no-hardcoded-credentials
    patterns:
      - pattern: $KEY = "..."
    message: "Potential hardcoded credential detected"
    severity: ERROR
    languages: [python, javascript, typescript, java, go]
    metadata:
      cwe: "CWE-798"
      owasp: "A07:2021 - Identification and Authentication Failures"

# .github/workflows/sast.yml
- name: Semgrep SAST Scan
  uses: semgrep/semgrep-action@v1
  with:
    config: >-
      p/owasp-top-ten
      p/secrets
      p/python
      p/javascript
      .semgrep.yml
    publishToken: ${{ secrets.SEMGREP_APP_TOKEN }}
  env:
    SEMGREP_BASELINE_REF: ${{ github.base_ref }}  # Only report new findings on PRs
```

**CodeQL configuration:**
```yaml
# .github/workflows/codeql.yml
name: CodeQL Analysis
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 2 * * 1'  # Weekly full scan

jobs:
  analyze:
    runs-on: ubuntu-latest
    permissions:
      actions: read
      contents: read
      security-events: write

    strategy:
      matrix:
        language: [javascript, python, java]

    steps:
      - uses: actions/checkout@v4
      - uses: github/codeql-action/init@v3
        with:
          languages: ${{ matrix.language }}
          queries: +security-extended,security-and-quality

      - uses: github/codeql-action/autobuild@v3

      - uses: github/codeql-action/analyze@v3
        with:
          category: "/language:${{ matrix.language }}"
          upload: true  # Upload to GitHub Security tab
```

### SAST Tuning and False Positive Management

High false positive rates are the primary cause of developer distrust and SAST tool abandonment. Tuning strategies:

1. **Use incremental scanning** — on pull requests, only report findings introduced in the current diff
2. **Customize severity mappings** — adjust severity levels for findings based on organizational risk context
3. **Suppress with justification** — allow suppressions only with a documented business justification and expiry date
4. **Regular false positive review** — monthly review of suppression records; remove outdated suppressions
5. **Custom rules** — replace generic rules with organization-specific rules that reflect actual vulnerability patterns

---

## DAST Integration

Dynamic Application Security Testing evaluates a running application by sending test inputs and analyzing responses to identify vulnerabilities that require execution to detect.

### DAST Prerequisites

DAST requires a deployed, running instance of the application. This is typically the staging environment. Requirements:

- The staging environment must closely mirror production configuration
- Test user accounts must be provisioned for authenticated scanning
- APIs must have valid authentication tokens for the DAST tool
- The DAST tool must be able to reach all application endpoints from within the pipeline network

### OWASP ZAP Integration

OWASP ZAP is the most widely used open-source DAST tool. It can be integrated into CI/CD pipelines in several modes:

**Baseline scan (passive, fast — 5 minutes):**
```yaml
- name: ZAP Baseline Scan
  uses: zaproxy/action-baseline@v0.10.0
  with:
    target: 'https://staging.myapp.example.com'
    rules_file_name: '.zap/rules.tsv'
    cmd_options: '-a'  # Include alpha passive scan rules
    allow_issue_writing: true
    fail_action: warn  # Don't block; report findings
```

**Full scan (active, thorough — 30-60 minutes, use for release candidates):**
```yaml
- name: ZAP Full Scan
  uses: zaproxy/action-full-scan@v0.10.0
  with:
    target: 'https://staging.myapp.example.com'
    rules_file_name: '.zap/rules.tsv'
    cmd_options: '-z "-config scanner.maxScanDurationInMins=30"'
    allow_issue_writing: true
    fail_action: true  # Block on high findings for release candidates
```

**API scan (OpenAPI/Swagger-based):**
```yaml
- name: ZAP API Scan
  uses: zaproxy/action-api-scan@v0.6.0
  with:
    target: 'https://staging.myapp.example.com/openapi.yaml'
    format: openapi
    fail_action: true
    cmd_options: '-z "-config scanner.maxScanDurationInMins=20"'
```

### DAST Thresholds

| Finding Severity | Policy | Trigger |
|---|---|---|
| High / Critical | Block production promotion | DAST scan on staging before every production release |
| Medium | Required remediation plan | Within 30 days; tracked in vulnerability management |
| Low | Optional | Reviewed in quarterly security debt sessions |
| Informational | No action required | Available in scan reports |

### Authenticated DAST

Many vulnerability classes only appear in authenticated application flows. Configure authenticated scanning:

```yaml
# ZAP authentication script for form-based login
- name: ZAP Authenticated Scan
  uses: zaproxy/action-full-scan@v0.10.0
  with:
    target: 'https://staging.myapp.example.com'
    cmd_options: >-
      -config api.key=${{ secrets.ZAP_API_KEY }}
      -script /zap/scripts/auth-formlogin.js
    allow_issue_writing: true
  env:
    ZAP_AUTH_USERNAME: ${{ secrets.DAST_TEST_USERNAME }}
    ZAP_AUTH_PASSWORD: ${{ secrets.DAST_TEST_PASSWORD }}
```

---

## SCA and Dependency Scanning

Software Composition Analysis identifies vulnerabilities in open-source and third-party dependencies used by the application.

### Dependency Vulnerability Scanning

**Snyk SCA integration:**
```yaml
- name: Snyk SCA Scan
  uses: snyk/actions/node@master
  continue-on-error: false
  env:
    SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
  with:
    args: >-
      --severity-threshold=high
      --fail-on=upgradable
      --sarif-file-output=snyk-results.sarif
      --org=${{ vars.SNYK_ORG_ID }}

- name: Upload Snyk results to GitHub Security tab
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: snyk-results.sarif
```

**OWASP Dependency-Check (Java/Maven):**
```yaml
- name: OWASP Dependency-Check
  uses: dependency-check/Dependency-Check_Action@main
  with:
    project: 'myapp'
    path: '.'
    format: 'SARIF'
    args: >
      --failOnCVSS 7
      --enableRetired
      --enableExperimental
      --nvdApiKey ${{ secrets.NVD_API_KEY }}

- name: Upload OWASP DC results
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: reports/dependency-check-report.sarif
```

### License Compliance Scanning

License violations can create legal liability. FOSSA provides automated license scanning:

```yaml
- name: FOSSA License Scan
  uses: fossas/fossa-action@v1
  with:
    api-key: ${{ secrets.FOSSA_API_KEY }}
    run-tests: true  # Fail if license policy violations detected
```

### Dependency Update Automation

Automated dependency update tools keep dependencies current and minimize vulnerability exposure windows:

**Dependabot configuration (`.github/dependabot.yml`):**
```yaml
version: 2
updates:
  - package-ecosystem: npm
    directory: /
    schedule:
      interval: weekly
      day: monday
      time: "09:00"
    open-pull-requests-limit: 10
    groups:
      production-dependencies:
        dependency-type: production
    ignore:
      - dependency-name: "*"
        update-types: ["version-update:semver-major"]
    reviewers:
      - "@security-champions-team"

  - package-ecosystem: docker
    directory: /
    schedule:
      interval: weekly
    reviewers:
      - "@platform-team"
```

### Dependency Pinning Strategy

All dependencies should be pinned to exact versions in lock files:
- `package-lock.json` / `yarn.lock` for Node.js (commit these files)
- `requirements.txt` with `==` for Python; use `pip-compile` for reproducibility
- `go.sum` for Go (commit this file)
- `Cargo.lock` for Rust (commit this file)
- Docker base images pinned to digest: `FROM ubuntu:22.04@sha256:<digest>`
- GitHub Actions pinned to commit SHA: `uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683`

---

## Secrets Detection and Management in Pipelines

### Pre-commit Secrets Detection

Prevent secrets from entering version control:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.4
    hooks:
      - id: gitleaks

  - repo: https://github.com/Yelp/detect-secrets
    rev: v1.4.0
    hooks:
      - id: detect-secrets
        args: ['--baseline', '.secrets.baseline']
        exclude: (package.lock.json|yarn.lock|\.secrets\.baseline)
```

### CI Pipeline Secrets Scanning

```yaml
# Gitleaks in GitHub Actions
- name: Gitleaks Secret Scan
  uses: gitleaks/gitleaks-action@v2
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
    GITLEAKS_LICENSE: ${{ secrets.GITLEAKS_LICENSE }}
  with:
    config-path: .gitleaks.toml

# Custom Gitleaks rules (.gitleaks.toml)
# title = "Custom Gitleaks Config"
# [extend]
# useDefault = true
# [[rules]]
# id = "company-api-key"
# description = "Company internal API key format"
# regex = '''MYCO-[A-Z0-9]{32}'''
# tags = ["key", "company"]
```

### Secrets Management Architecture

**Secret injection at runtime (never baked into images):**

```yaml
# GitHub Actions: OIDC + AWS Secrets Manager
- name: Configure AWS credentials
  uses: aws-actions/configure-aws-credentials@v4
  with:
    role-to-assume: ${{ vars.AWS_DEPLOY_ROLE_ARN }}
    aws-region: us-east-1

- name: Get secrets from AWS Secrets Manager
  uses: aws-actions/aws-secretsmanager-get-secrets@v2
  with:
    secret-ids: |
      production/myapp/database-credentials
      production/myapp/api-keys
    parse-json-secrets: true

# Secrets are now available as environment variables:
# ${{ env.PRODUCTION_MYAPP_DATABASE_CREDENTIALS_DB_PASSWORD }}
```

**Vault Agent secret injection in Kubernetes:**
```yaml
# Pod annotation for Vault Agent injector
annotations:
  vault.hashicorp.com/agent-inject: "true"
  vault.hashicorp.com/agent-inject-status: "update"
  vault.hashicorp.com/role: "myapp-k8s-role"
  vault.hashicorp.com/agent-inject-secret-config.env: "secret/data/production/myapp"
  vault.hashicorp.com/agent-inject-template-config.env: |
    {{ with secret "secret/data/production/myapp" -}}
    export DATABASE_URL="{{ .Data.data.database_url }}"
    export API_KEY="{{ .Data.data.api_key }}"
    {{- end }}
```

---

## Container Image Scanning

### Trivy Container Scanning

Trivy is a comprehensive, fast open-source vulnerability scanner for container images, file systems, and IaC configurations.

```yaml
- name: Build container image
  run: docker build -t ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }} .

- name: Run Trivy image scan
  uses: aquasecurity/trivy-action@master
  with:
    image-ref: '${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }}'
    format: 'sarif'
    output: 'trivy-results.sarif'
    severity: 'CRITICAL,HIGH'
    exit-code: '1'              # Fail the build on CRITICAL or HIGH
    ignore-unfixed: true        # Only report vulnerabilities with available fixes
    vuln-type: 'os,library'     # Scan both OS packages and application libraries

- name: Upload Trivy results
  uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: 'trivy-results.sarif'
```

### Image Scanning Policy

| Condition | Policy |
|---|---|
| Critical CVE (CVSS >= 9.0) with fix available | Block image promotion; must update base image |
| Critical CVE (CVSS >= 9.0) no fix available | Security team review; time-limited exception only |
| High CVE (CVSS 7.0–8.9) with fix available | Block image promotion to production; fix within 7 days |
| High CVE no fix available | Risk accepted with documentation; re-evaluate weekly |
| Medium CVE | Non-blocking; remediate within 30 days |

### Base Image Hardening

Use minimal base images to reduce the attack surface:

| Base Image | Use Case | Notes |
|---|---|---|
| `scratch` | Statically compiled binaries (Go) | Minimal possible attack surface |
| `gcr.io/distroless/static-debian12` | Static binaries needing libc | Google-maintained minimal image |
| `gcr.io/distroless/base-debian12` | Applications needing glibc | No shell, no package manager |
| `alpine:3.19` | Applications needing a shell | Minimal; musl-libc; active maintenance |
| `ubuntu:22.04-minimal` | Applications needing apt packages | Reduced ubuntu without snap/documentation |

---

## Artifact Signing and Verification

### Cosign / Sigstore Keyless Signing

Sigstore's keyless signing uses short-lived certificates tied to OIDC identities. No private key management required.

**Signing in GitHub Actions:**
```yaml
- name: Install Cosign
  uses: sigstore/cosign-installer@v3

- name: Sign container image
  run: |
    cosign sign --yes \
      --rekor-url=https://rekor.sigstore.dev \
      ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}@${{ steps.build.outputs.digest }}
  env:
    # COSIGN_EXPERIMENTAL is set automatically in GitHub Actions OIDC context
    COSIGN_EXPERIMENTAL: "1"
```

**Attach SBOM attestation:**
```yaml
- name: Generate SBOM with Syft
  uses: anchore/sbom-action@v0
  with:
    image: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }}
    format: spdx-json
    output-file: sbom.spdx.json

- name: Attest SBOM with Cosign
  run: |
    cosign attest --yes \
      --predicate sbom.spdx.json \
      --type spdxjson \
      ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}@${{ steps.build.outputs.digest }}
```

**Verification with Kyverno admission policy:**
```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-image-signature
spec:
  validationFailureAction: Enforce
  background: false
  rules:
    - name: check-image-signature
      match:
        any:
          - resources:
              kinds: [Pod]
              namespaces: [production]
      verifyImages:
        - imageReferences:
            - "ghcr.io/myorg/*"
          attestors:
            - entries:
                - keyless:
                    subject: "https://github.com/myorg/myrepo/.github/workflows/release.yml@refs/heads/main"
                    issuer: "https://token.actions.githubusercontent.com"
                    rekor:
                      url: https://rekor.sigstore.dev
```

---

## Deployment Strategies

### Blue/Green Deployment

Blue/green deployment maintains two identical production environments. Traffic switches instantly from the blue (current) to the green (new) environment, with the ability to roll back in seconds.

```yaml
# Argo Rollouts blue/green deployment
apiVersion: argoproj.io/v1alpha1
kind: Rollout
metadata:
  name: myapp
spec:
  replicas: 5
  strategy:
    blueGreen:
      activeService: myapp-active
      previewService: myapp-preview
      autoPromotionEnabled: false  # Require manual promotion
      prePromotionAnalysis:
        templates:
          - templateName: success-rate
        args:
          - name: service-name
            value: myapp-preview
      postPromotionAnalysis:
        templates:
          - templateName: success-rate
  selector:
    matchLabels:
      app: myapp
  template:
    # ... pod template
```

### Canary Deployment

Canary deployments gradually shift traffic to the new version, enabling automated rollback if error rates or latency exceed thresholds.

```yaml
# Argo Rollouts canary strategy
spec:
  strategy:
    canary:
      steps:
        - setWeight: 5     # 5% of traffic to new version
        - pause: {duration: 5m}
        - analysis:
            templates:
              - templateName: success-rate
        - setWeight: 25
        - pause: {duration: 10m}
        - analysis:
            templates:
              - templateName: success-rate
        - setWeight: 50
        - pause: {duration: 10m}
        - setWeight: 100
      canaryService: myapp-canary
      stableService: myapp-stable
      trafficRouting:
        nginx:
          stableIngress: myapp-stable-ingress
```

---

## Audit Logging Requirements

### Required Pipeline Audit Events

The following events must be logged for every CI/CD pipeline with timestamps, actor identity, and outcome:

| Event | Required Fields | Retention |
|---|---|---|
| Pipeline triggered | Trigger type (push/PR/manual/schedule), actor, branch/tag, commit SHA | 365 days |
| Secret accessed | Secret name (not value), actor (pipeline run identity), timestamp | 365 days |
| Artifact built | Image digest, commit SHA, build ID, builder identity | 365 days |
| Artifact signed | Artifact digest, signing identity, transparency log entry ID | 365 days |
| Deployment initiated | Target environment, artifact digest, actor, approval record | 365 days |
| Security gate result | Gate type, result (pass/fail), findings count by severity, threshold | 365 days |
| Permission granted/revoked | Actor, target resource, permissions, grantor | 365 days |
| Pipeline configuration changed | Changed file, actor, commit SHA, before/after diff | 365 days |

### Audit Log Integrity

Audit logs must be protected from tampering:
- Write audit logs to a separate, append-only storage system (not the same system they monitor)
- Configure log shipping to immutable log storage (AWS CloudTrail, S3 Object Lock, Worm storage)
- Enable log integrity validation (AWS CloudTrail log file validation)
- Alert on log gaps or tampering detection

---

## Compliance Considerations

### SOC 2 Type II Mapping

| SOC 2 Common Criterion | CI/CD Control | Evidence |
|---|---|---|
| CC6.1 — Logical access controls | Pipeline RBAC; OIDC federation; least-privilege tokens | IAM policy configs; access review records |
| CC6.2 — Prior to access | Approval workflows for production deployments | Deployment approval records |
| CC6.3 — Revocation of access | Automated secret rotation; OIDC short-lived tokens | Rotation logs; token TTL configs |
| CC7.2 — Monitoring of system components | SIEM pipeline event monitoring; anomaly detection | SIEM dashboards; alert records |
| CC8.1 — Change management | Branch protection; code review; deployment approvals | PR review logs; change management records |
| A1.1 — Availability commitments | Progressive deployment; automated rollback; canary analysis | Rollout configuration; availability metrics |

### PCI-DSS v4.0 Mapping

| PCI-DSS Requirement | CI/CD Control | Notes |
|---|---|---|
| Req 6.3.1 — Vulnerability management | SAST/SCA/DAST in pipeline | All production code scanned before deployment |
| Req 6.3.3 — Patch management | Automated dependency updates; Dependabot | Patches tracked and applied within requirements |
| Req 6.4.1 — Web app protection | DAST scanning; WAF controls | DAST run against staging before production |
| Req 6.5 — Secure development practices | Security training; code review; SAST | Training records; PR review logs |
| Req 8.2 — User identification | SSO for all pipeline tools; MFA enforced | SSO configuration; MFA enrollment records |
| Req 10.2 — Audit log generation | Pipeline audit events forwarded to SIEM | SIEM ingestion confirmation; log samples |
| Req 10.3 — Audit log protection | Immutable audit log storage | S3 Object Lock config; CloudTrail config |
| Req 12.3.4 — Technology review | Quarterly pipeline security review | Review records and action items |

### ISO 27001:2022 Mapping

| ISO 27001 Control | CI/CD Implementation |
|---|---|
| A.8.8 — Management of technical vulnerabilities | Continuous SCA; defined vulnerability SLAs; patch management |
| A.8.20 — Networks security | Pipeline network segmentation; egress controls |
| A.8.25 — Secure development lifecycle | Security requirements; code review; security testing in SDLC |
| A.8.26 — Application security requirements | Threat modeling; security acceptance criteria in user stories |
| A.8.27 — Secure system architecture and engineering | Reference architecture; security design reviews |
| A.8.28 — Secure coding | Secure coding guidelines; SAST in IDE and CI |
| A.8.29 — Security testing | SAST, DAST, SCA, penetration testing in pipeline |
| A.8.30 — Outsourced development | Third-party code review; SCA for vendor dependencies |
| A.8.31 — Separation of development, test, production | Environment segregation; separate credentials |
| A.8.32 — Change management | Branch protection; code review; deployment approvals |
