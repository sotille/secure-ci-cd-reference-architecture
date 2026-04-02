# Secure CI/CD Implementation Roadmap

## Table of Contents

- [Roadmap Overview](#roadmap-overview)
- [Quick Wins: 0–30 Days](#quick-wins-030-days)
- [Medium Term: 30–90 Days](#medium-term-3090-days)
- [Long Term: 90–180 Days](#long-term-90180-days)
- [Maturity Model for CI/CD Security](#maturity-model-for-cicd-security)
- [Metrics to Track Progress](#metrics-to-track-progress)
- [Toolchain Evolution Path](#toolchain-evolution-path)

---

## Roadmap Overview

Securing a CI/CD pipeline is a multi-month initiative that benefits from a phased approach. Attempting to implement all controls simultaneously creates implementation chaos, delivery disruption, and organizational resistance. This roadmap sequences security improvements to maximize impact in the shortest time, establishing a secure baseline quickly while building toward a comprehensive defense-in-depth posture over six months.

### Phasing Philosophy

- **Days 0–30 (Quick Wins):** High-impact, low-effort controls that eliminate the most dangerous CI/CD attack vectors without requiring significant infrastructure changes
- **Days 30–90 (Medium Term):** Systematic hardening that addresses the full CI/CD security control framework; requires infrastructure investment and process changes
- **Days 90–180 (Long Term):** Advanced controls, optimization, and maturity advancement; prepares the organization for compliance certification and continuous improvement

### Assumptions

This roadmap assumes:
- Git-based source control (GitHub, GitLab, or Bitbucket) is in use
- At least one CI/CD platform is operational (GitHub Actions, GitLab CI, Jenkins, or equivalent)
- A Kubernetes-based deployment target exists (or cloud-native equivalent)
- The organization has security engineering resources to implement and maintain controls
- Budget has been approved for tooling as detailed in the Toolchain Evolution section

---

## Quick Wins: 0–30 Days

The 0–30 day phase targets controls that can be implemented in days or weeks and immediately address the highest-frequency CI/CD attack vectors: exposed secrets, unverified dependencies, and misconfigured access controls.

### Week 1: Secret Scanning and Baseline Visibility

**Day 1–2: Enable Built-in Secret Scanning**

GitHub organizations:
```bash
# Enable secret scanning on all repositories via GitHub API
gh api \
  --method PATCH \
  -H "Accept: application/vnd.github+json" \
  /orgs/MYORG \
  -f security_and_analysis_setting='{"secret_scanning": {"status": "enabled"}, "secret_scanning_push_protection": {"status": "enabled"}}'
```

GitLab groups:
```bash
# Enable secret detection in .gitlab-ci.yml
include:
  - template: Security/Secret-Detection.gitlab-ci.yml
```

**Day 2–3: Run Historical Secret Scan**

```bash
# Scan all repositories for secrets in git history
# Run from a clone with full history
gitleaks detect \
  --source . \
  --verbose \
  --redact \
  --report-format sarif \
  --report-path historical-secrets.sarif

# For organizations with many repositories, use gitleaks' Git provider scanning
gitleaks github \
  --org MYORG \
  --access-token $GITHUB_PAT \
  --report-path org-secrets.json
```

**Action on findings:** Rotate every exposed secret immediately. Then clean git history.

**Day 3–5: Run SCA Baseline Scan**

```bash
# Run Snyk across all repositories to get vulnerability baseline
snyk test --all-projects --json > baseline-sca-results.json

# Parse results to count Critical/High by repository
cat baseline-sca-results.json | \
  jq '.[] | {repo: .name, critical: (.vulnerabilities | map(select(.severity == "critical")) | length), high: (.vulnerabilities | map(select(.severity == "high")) | length)}'
```

**Deliverable:** Vulnerability baseline report with Critical/High counts by repository. Prioritize top 5 repositories for immediate remediation.

---

### Week 2: Source Control Hardening

**Branch Protection on All Production Repositories**

```python
# Python script to apply branch protection to all org repositories
import requests

headers = {"Authorization": f"token {GITHUB_TOKEN}", "Accept": "application/vnd.github.v3+json"}

protection_rules = {
    "required_status_checks": {
        "strict": True,
        "contexts": []  # Will be populated as CI checks are added
    },
    "enforce_admins": True,
    "required_pull_request_reviews": {
        "dismiss_stale_reviews": True,
        "require_code_owner_reviews": False,
        "required_approving_review_count": 1
    },
    "restrictions": None,
    "allow_force_pushes": False,
    "allow_deletions": False,
    "required_conversation_resolution": True
}

repos = requests.get(f"https://api.github.com/orgs/{ORG}/repos?per_page=100", headers=headers).json()
for repo in repos:
    requests.put(
        f"https://api.github.com/repos/{ORG}/{repo['name']}/branches/main/protection",
        json=protection_rules,
        headers=headers
    )
    print(f"Protected: {repo['name']}")
```

**Enable Dependabot for All Repositories**

```yaml
# .github/dependabot.yml — commit to all production repositories
version: 2
updates:
  - package-ecosystem: npm
    directory: /
    schedule:
      interval: weekly
  - package-ecosystem: pip
    directory: /
    schedule:
      interval: weekly
  - package-ecosystem: docker
    directory: /
    schedule:
      interval: weekly
  - package-ecosystem: github-actions
    directory: /
    schedule:
      interval: weekly
```

---

### Week 3: Pre-Commit Hooks and Immediate CI Integration

**Deploy Pre-Commit Framework**

```bash
# Create organization-wide pre-commit template
# Store this in a centralized repository consumed by all projects
cat > .pre-commit-config.yaml << 'EOF'
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.4
    hooks:
      - id: gitleaks

  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.5.0
    hooks:
      - id: detect-private-key
      - id: check-added-large-files
        args: ['--maxkb=2000']
      - id: no-commit-to-branch
        args: ['--branch', 'main', '--branch', 'master']

  - repo: https://github.com/bridgecrewio/checkov
    rev: '3.2.0'
    hooks:
      - id: checkov
        args: [--soft-fail]  # Warn only in pre-commit; hard fail in CI
EOF

pre-commit install
pre-commit install --hook-type commit-msg
```

**Add Secrets Scanning to All CI Pipelines (Blocking)**

This is the one security control that should be blocking from day one — there is no legitimate reason for secrets to be in source code or build artifacts.

```yaml
# Add to every CI pipeline immediately
secrets-scan:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
      with:
        fetch-depth: 0
    - uses: gitleaks/gitleaks-action@v2
      env:
        GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
      # Gitleaks exits non-zero if secrets are found — build fails
```

---

### Week 4: CI Security Baseline (Warning Mode)

Add SAST and SCA to all CI pipelines in warning mode. Do not block yet — the goal is to establish baselines and alert teams to findings.

```yaml
# Quick-start security scan job (add to every pipeline)
security-baseline:
  runs-on: ubuntu-latest
  continue-on-error: true  # Warning mode — do not block yet

  steps:
    - uses: actions/checkout@v4
      with:
        fetch-depth: 0

    # SAST: Semgrep (fast, good coverage)
    - name: Semgrep SAST
      uses: semgrep/semgrep-action@v1
      with:
        config: p/owasp-top-ten p/secrets
        publishToken: ${{ secrets.SEMGREP_APP_TOKEN }}
      continue-on-error: true

    # SCA: GitHub-native (no additional tool setup required)
    # GitHub Dependency Review is automatically available if Advanced Security is enabled

    # Container scan (if applicable)
    - name: Build image
      run: docker build -t scan-target:${{ github.sha }} .
      if: hashFiles('Dockerfile') != ''

    - name: Trivy scan
      uses: aquasecurity/trivy-action@master
      if: hashFiles('Dockerfile') != ''
      with:
        image-ref: scan-target:${{ github.sha }}
        format: sarif
        output: trivy.sarif
        exit-code: '0'  # Warning mode
      continue-on-error: true
```

**30-Day Checkpoint Metrics:**
- % repositories with secret scanning enabled: 100%
- Exposed secrets cleaned from version control: confirmed
- % repositories with branch protection: 100%
- % CI pipelines with security baseline scanning: 100%
- Baseline vulnerability counts documented

---

## Medium Term: 30–90 Days

The 30–90 day phase activates security gates, introduces IaC and container security, deploys secrets management infrastructure, and integrates DAST.

### Days 30–45: Gate Activation and IaC Security

**Activate Security Gates**

Transition from warning mode to blocking. Teams should have received notifications of their outstanding findings during the warning period and had 2 weeks to begin remediation.

```yaml
# Updated pipeline — gates now blocking
security-scan:
  runs-on: ubuntu-latest
  # No more continue-on-error
  steps:
    - uses: actions/checkout@v4
      with:
        fetch-depth: 0

    - name: Semgrep SAST (BLOCKING on Critical/High)
      uses: semgrep/semgrep-action@v1
      with:
        config: p/owasp-top-ten p/secrets
        publishToken: ${{ secrets.SEMGREP_APP_TOKEN }}
      # Semgrep exits non-zero on errors (Critical findings) — build fails

    - name: Snyk SCA (BLOCKING on Critical/High)
      uses: snyk/actions/node@master
      env:
        SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
      with:
        args: --severity-threshold=high --fail-on=all
```

**IaC Security Scanning**

```yaml
iac-security:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4

    - name: Checkov IaC scan
      uses: bridgecrewio/checkov-action@master
      with:
        directory: .
        framework: terraform,dockerfile,kubernetes
        hard_fail_on: HIGH,CRITICAL
        output_format: sarif
        output_file_path: checkov.sarif

    - name: Upload results
      uses: github/codeql-action/upload-sarif@v3
      if: always()
      with:
        sarif_file: checkov.sarif
```

---

### Days 45–60: Container Security and SBOM

**Container Scanning with Blocking Gate**

```yaml
container-security:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4

    - name: Build container image
      run: docker build -t ${{ env.IMAGE_TAG }} .

    - name: Trivy scan (BLOCKING on Critical)
      uses: aquasecurity/trivy-action@master
      with:
        image-ref: ${{ env.IMAGE_TAG }}
        format: sarif
        output: trivy.sarif
        severity: CRITICAL,HIGH
        exit-code: '1'       # Block on Critical/High
        ignore-unfixed: true

    - name: Upload results
      uses: github/codeql-action/upload-sarif@v3
      if: always()
      with:
        sarif_file: trivy.sarif
```

**SBOM Generation**

```yaml
    - name: Generate SBOM
      uses: anchore/sbom-action@v0
      with:
        image: ${{ env.IMAGE_TAG }}
        format: spdx-json
        output-file: sbom.spdx.json
        artifact-name: sbom-${{ github.sha }}.spdx.json
      # SBOM stored as workflow artifact and attached to container image
```

---

### Days 60–75: Secrets Management and OIDC

**Deploy Vault or Cloud-Native Secrets Manager**

For AWS-based organizations — migrate to AWS Secrets Manager with OIDC:

```yaml
# Remove stored AWS credentials; replace with OIDC
# Before: AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY stored as secrets
# After: OIDC federation — no credentials stored

jobs:
  deploy:
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ vars.AWS_DEPLOY_ROLE_ARN }}
          aws-region: us-east-1
          # Credentials auto-expire after 1 hour
```

**Secrets Migration Checklist:**
- [ ] Audit all pipeline secrets in GitHub/GitLab/Jenkins secrets stores
- [ ] Identify which secrets can be replaced with OIDC (cloud provider credentials)
- [ ] Migrate remaining secrets to Vault/AWS SM/Azure KV
- [ ] Delete original secrets from CI/CD platform secrets stores
- [ ] Verify pipelines still function with migrated secrets
- [ ] Enable Vault audit logging and forward to SIEM

---

### Days 75–90: DAST Integration

**Staging DAST Scan**

```yaml
# Runs after deployment to staging environment
dast-staging:
  needs: [deploy-staging]
  runs-on: ubuntu-latest
  steps:
    - name: ZAP Baseline Scan
      uses: zaproxy/action-baseline@v0.10.0
      with:
        target: ${{ vars.STAGING_URL }}
        rules_file_name: '.zap/rules.tsv'
        fail_action: true  # Block production promotion if High findings

    - name: ZAP API Scan
      if: hashFiles('openapi.yaml') != ''
      uses: zaproxy/action-api-scan@v0.6.0
      with:
        target: ${{ vars.STAGING_URL }}/openapi.yaml
        format: openapi
        fail_action: true
```

**60-Day and 90-Day Checkpoint Metrics:**

| Metric | Target at Day 60 | Target at Day 90 |
|---|---|---|
| Security gate pass rate (first attempt) | > 75% | > 85% |
| % artifacts with SBOM | > 80% | 100% |
| Long-lived cloud credentials in pipelines | 0 | 0 |
| Vulnerability SLA compliance (Critical) | > 80% | > 90% |
| DAST coverage (% staging pipelines) | > 50% | 100% |
| IaC scan coverage | > 70% | 100% |

---

## Long Term: 90–180 Days

The 90–180 day phase focuses on infrastructure hardening, artifact signing, runtime security, and maturity advancement.

### Days 90–120: Infrastructure Hardening

**Ephemeral Runner Deployment**

```yaml
# GitHub Actions Runner Scale Set (Kubernetes)
# helm install arc-runner-set oci://ghcr.io/actions/actions-runner-controller-charts/gha-runner-scale-set \
#   --set githubConfigUrl=https://github.com/MYORG \
#   --set githubConfigSecret=arc-github-secret \
#   --set containerMode.type=kubernetes \
#   --set minRunners=0 \
#   --set maxRunners=10

# Runner pod template with security hardening
containerMode:
  type: kubernetes
  kubernetesModeServiceAccount: arc-runner
  kubernetesModeWorkVolumeClaim:
    accessModes: ["ReadWriteOnce"]
    storageClassName: standard
    resources:
      requests:
        storage: 1Gi
# Pods are ephemeral and destroyed after each job
```

**Network Egress Policies**

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: arc-runner-egress
  namespace: arc-systems
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/part-of: gha-runner-scale-set
  policyTypes: [Egress]
  egress:
    - ports: [{port: 53, protocol: UDP}]                    # DNS
    - to: [{ipBlock: {cidr: "140.82.112.0/20"}}]            # GitHub
    - to: [{ipBlock: {cidr: "192.30.252.0/22"}}]            # GitHub
    - to: [{namespaceSelector: {matchLabels: {name: artifact-registry}}}]
```

---

### Days 120–150: Artifact Signing and Admission Control

**Implement Cosign Signing**

```yaml
# Add to all release pipelines
sign-artifact:
  needs: [build, container-security]
  if: github.ref == 'refs/heads/main'
  runs-on: ubuntu-latest
  permissions:
    contents: read
    packages: write
    id-token: write
  steps:
    - uses: sigstore/cosign-installer@v3

    - name: Sign image
      run: |
        cosign sign --yes \
          --rekor-url=https://rekor.sigstore.dev \
          ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}@${{ needs.build.outputs.digest }}

    - name: Attest SBOM
      run: |
        cosign attest --yes \
          --predicate sbom.spdx.json \
          --type spdxjson \
          ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}@${{ needs.build.outputs.digest }}
```

**Deploy Kyverno Admission Controller**

```bash
# Install Kyverno
helm repo add kyverno https://kyverno.github.io/kyverno/
helm install kyverno kyverno/kyverno \
  --namespace kyverno \
  --create-namespace \
  --set admissionController.replicas=3

# Apply image verification policy (see architecture.md for full policy)
kubectl apply -f kyverno-verify-image-signature.yaml
```

---

### Days 150–180: Runtime Security and Maturity Validation

**Deploy Falco**

```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm install falco falcosecurity/falco \
  --namespace falco \
  --create-namespace \
  --set falcosidekick.enabled=true \
  --set falcosidekick.config.slack.webhookurl=$SLACK_WEBHOOK \
  --set falcosidekick.config.slack.outputformat=fields \
  --set falcosidekick.config.customfields="env:production"
```

**Custom Falco Rules for CI/CD Environments:**

```yaml
# /etc/falco/rules.d/cicd-rules.yaml
- rule: Unexpected Outbound Connection from CI/CD Runner
  desc: Detects outbound connections to non-approved destinations from CI/CD runners
  condition: >
    outbound and
    container.label.role = "ci-runner" and
    not dest.domain in (approved_ci_domains)
  output: >
    Unexpected outbound connection from CI/CD runner
    (user=%user.name container=%container.name dest=%fd.rip:%fd.rport)
  priority: WARNING
  tags: [cicd, network]

- rule: Sensitive File Access in CI/CD Container
  desc: Detects access to sensitive files from CI/CD runner containers
  condition: >
    open_read and
    container.label.role = "ci-runner" and
    fd.name in (sensitive_files) and
    not proc.name in (approved_readers)
  output: >
    Sensitive file access in CI/CD container
    (user=%user.name file=%fd.name proc=%proc.name)
  priority: ERROR
  tags: [cicd, filesystem]
```

**180-Day Final Assessment:**

Conduct a comprehensive security assessment against the CI/CD Security Maturity Model to validate progress.

---

## Maturity Model for CI/CD Security

### Level 1: Ad Hoc

**Characteristics:**
- No systematic secret management; credentials stored directly in pipeline config
- No dependency vulnerability scanning
- No container image scanning
- Overly permissive pipeline tokens (often org-level admin)
- No branch protection or code review requirements
- Pipeline configuration not version-controlled or reviewed
- No audit logging

**Risk profile:** Critical — common attack vectors fully exploitable

---

### Level 2: Basic Controls

**Characteristics:**
- Secret scanning enabled on repositories
- Basic SCA scanning runs in CI pipelines (may not be blocking)
- Branch protection with required reviews on default branches
- Container images scanned (may not be blocking)
- Cloud credentials stored as CI/CD secrets (not OIDC)
- Some audit logging but not centralized

**Risk profile:** High — most common attacks mitigated; sophisticated attacks possible

---

### Level 3: Systematic Security

**Characteristics:**
- All of Level 2, plus:
- Blocking SAST, SCA, and secrets gates on all production pipelines
- IaC security scanning with blocking gates
- OIDC federation for cloud provider authentication
- Centralized secrets management (Vault or cloud-native)
- SBOM generated for every production artifact
- DAST integrated into pre-production pipeline
- Deployment approval required for production
- Centralized, structured audit logging
- Security Champion per development team

**Risk profile:** Medium — standard attacks well-defended; targeted sophisticated attacks require significant effort

---

### Level 4: Hardened Infrastructure

**Characteristics:**
- All of Level 3, plus:
- Ephemeral build environments (no state persistence between builds)
- Network egress controls on build environments
- Artifact signing with Cosign; admission control enforces verification
- Progressive deployment with automated rollback
- Runtime security monitoring (Falco) in production
- CSPM for cloud configuration compliance
- Security anomaly detection for pipeline behavior
- SLSA Level 2+ provenance for all artifacts

**Risk profile:** Low-Medium — industry-standard security posture; advanced persistent threats remain possible

---

### Level 5: Continuous Assurance

**Characteristics:**
- All of Level 4, plus:
- SLSA Level 3+ with full provenance verification
- Automated SBOM vulnerability monitoring with continuous CVE scanning
- Behavioral anomaly detection with ML-based baselines
- Third-party penetration testing of CI/CD infrastructure annually
- Bug bounty program for pipeline-related vulnerabilities
- Compliance-as-code with automated evidence collection
- All controls continuously monitored with SLO-based alerting
- Security KPIs improving quarter-over-quarter

**Risk profile:** Low — industry-leading pipeline security; near-complete coverage of known attack vectors

---

## Metrics to Track Progress

### Foundation Metrics (Track from Day 1)

| Metric | Description | Tool |
|---|---|---|
| % repos with secret scanning | Ratio of repos with active secret scanning to total | GitHub/GitLab security overview |
| Exposed secrets count | Number of unrotated exposed secrets | Secret scanning findings |
| % pipelines with SAST | Ratio of pipelines with active SAST | CI/CD platform API |
| % pipelines with SCA | Ratio of pipelines with active SCA | CI/CD platform API |
| Critical CVE count (total) | Total unmitigated Critical CVEs across all repositories | Snyk/Dependabot/Mend |
| % repos with branch protection | Ratio of production repos with branch protection | GitHub/GitLab API |

### Security Gate Metrics (Track from Day 30)

| Metric | Description | Target at 90 days |
|---|---|---|
| Security gate pass rate | % of PR builds that pass all security gates on first try | > 85% |
| Mean time to remediate — Critical | Average days from Critical CVE discovery to closure | < 48 hours |
| Mean time to remediate — High | Average days from High finding discovery to closure | < 7 days |
| Exception rate | % of security gate failures resolved via exception (vs. fix) | < 5% |
| False positive rate | % of SAST findings classified as false positive | < 25% |

### Advanced Metrics (Track from Day 90)

| Metric | Description | Target at 180 days |
|---|---|---|
| % artifacts with SBOM | Coverage of SBOM generation across production artifacts | 100% |
| % images signed | Coverage of Cosign signing across production images | 100% |
| % deployments with admitted signed image | % production deployments where admission controller verified signature | 100% |
| Mean time to detect pipeline anomaly | Time from anomalous behavior to alert generation | < 1 hour |
| SLSA provenance coverage | % of artifacts with SLSA provenance attestation | > 80% |
| Compliance control automation | % of compliance evidence collected automatically | > 70% |

---

## Toolchain Evolution Path

The toolchain evolves through three phases corresponding to the roadmap phases. This progression moves from free/low-cost quick-start tools to a comprehensive, integrated enterprise toolchain.

### Phase 1 Toolchain (Days 0–30)

**Cost:** $0–$5K/month (mostly GitHub Advanced Security or GitLab Ultimate tier)

| Category | Tool |
|---|---|
| Secret scanning | GitHub Secret Scanning (built-in), Gitleaks |
| SAST | Semgrep (OSS), CodeQL (GitHub Advanced Security) |
| SCA | GitHub Dependabot, Snyk Free |
| Container scanning | Trivy (OSS) |
| IaC scanning | Checkov (OSS) |
| Pre-commit | Gitleaks, pre-commit framework |
| Artifact storage | GHCR or existing registry |

---

### Phase 2 Toolchain (Days 30–90)

**Additional cost:** $5K–$20K/month depending on organization size

| Category | Tool Upgrade |
|---|---|
| SAST | Semgrep OSS → Semgrep AppSec Platform (for organization-wide management) |
| SCA | Dependabot → Snyk Pro or Mend (better coverage, policy management) |
| Secrets management | Platform secrets → HashiCorp Vault OSS or AWS Secrets Manager |
| DAST | OWASP ZAP (OSS) |
| Vulnerability management | DefectDojo (OSS) or Snyk dashboard |
| Container registry | Add Harbor for internal registry with built-in scanning |

---

### Phase 3 Toolchain (Days 90–180+)

**Additional cost:** $15K–$50K/month at enterprise scale

| Category | Tool Upgrade / Addition |
|---|---|
| Runtime security | Falco (OSS) → Sysdig (commercial) for enterprise features |
| CSPM | Wiz or Prisma Cloud for comprehensive cloud security posture |
| Artifact signing | Cosign (OSS) — no additional cost |
| Admission control | Kyverno (OSS) or OPA Gatekeeper (OSS) |
| Behavior analytics | SIEM (Splunk, Microsoft Sentinel, or Elastic SIEM) |
| Supply chain | Dependency-Track for SBOM management |
| Compliance automation | Chef InSpec or AWS Config with custom rules |
| Pen testing | Annual engagement with a security firm |

### Toolchain Evaluation Triggers

Review and potentially update toolchain when:
- Current tool's false positive rate exceeds 30% despite tuning efforts
- Current tool misses a vulnerability class exploited in a security incident
- A new vulnerability category emerges (e.g., new OWASP Top 10 entry)
- Vendor discontinues a tool or significantly raises pricing
- A new open-source tool achieves significantly better performance benchmarks
- Compliance requirements mandate a specific tool's certifications
