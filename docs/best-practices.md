# Secure CI/CD Best Practices

This document catalogs 25+ best practices for secure CI/CD pipelines, organized by security domain. Each practice includes a rationale and concrete implementation guidance.

## Table of Contents

- [Source Code Security](#source-code-security)
- [Build Security](#build-security)
- [Test Security](#test-security)
- [Deployment Security](#deployment-security)
- [Secrets Management](#secrets-management)
- [Access Control](#access-control)
- [Audit and Compliance](#audit-and-compliance)

---

## Source Code Security

### BP-SRC-01: Enforce Signed Commits Across All Production Repositories

**Rationale:** Unsigned commits can be authored by anyone with push access and are trivially spoofed in certain scenarios. Commit signing using GPG or SSH keys provides cryptographic proof that a commit was created by a specific identity, supporting non-repudiation and enabling detection of unauthorized commit injection.

**Implementation:**
```bash
# Configure git to sign all commits with SSH key (simpler than GPG for most developers)
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519.pub
git config --global commit.gpgsign true

# Verify a commit's signature
git log --show-signature -1

# For organizations using Sigstore Gitsign (keyless, OIDC-based)
gitsign configure
# Signing keys are tied to OIDC identity; no key management required
```

Enforce via GitHub branch protection: `require_signed_commits = true` in Terraform or via Settings > Branches in the GitHub UI.

---

### BP-SRC-02: Configure Branch Protection Rules Comprehensively

**Rationale:** Without branch protection, any team member with write access can push directly to the default branch, bypassing code review, automated security tests, and pipeline security gates. Comprehensive branch protection ensures every change goes through the full security validation workflow.

**Implementation:**
```hcl
# Terraform: Comprehensive branch protection
resource "github_branch_protection" "main" {
  repository_id  = github_repository.app.node_id
  pattern        = "main"

  required_status_checks {
    strict   = true  # Branch must be up-to-date before merge
    contexts = [
      "security / secrets-scan",
      "security / sast",
      "security / sca",
      "security / container-scan",
      "security / iac-scan"
    ]
  }

  required_pull_request_reviews {
    dismiss_stale_reviews           = true   # Re-review required after new commits
    require_code_owner_reviews      = true   # CODEOWNERS must review
    required_approving_review_count = 2
    require_last_push_approval      = true   # Reviewer cannot also be last pusher
  }

  restrict_pushes {
    push_allowances = []  # No one can bypass via direct push
  }

  require_signed_commits          = true
  require_conversation_resolution = true
  allows_force_pushes             = false
  allows_deletions                = false
}
```

---

### BP-SRC-03: Use CODEOWNERS to Enforce Security Reviews for Sensitive Paths

**Rationale:** Security-sensitive code paths — authentication logic, authorization checks, cryptographic operations, payment flows, secret handling code — require review by someone with security expertise, not just any team member. CODEOWNERS automates this requirement.

**Implementation:**
```
# .github/CODEOWNERS

# Global fallback: any 2 developers can review general code
*                               @org/developers

# Authentication and authorization: requires security team review
/src/auth/                      @org/security-team @org/security-champions
/src/middleware/auth*           @org/security-team
/src/middleware/authz*          @org/security-team

# Payment processing
/src/payments/                  @org/security-team @org/payments-team

# Cryptographic operations
/src/crypto/                    @org/security-team
/src/encryption/                @org/security-team

# CI/CD pipeline configuration: requires platform security team
/.github/workflows/             @org/platform-security
/.gitlab-ci.yml                 @org/platform-security
/Jenkinsfile                    @org/platform-security

# IaC: requires platform team
/terraform/                     @org/platform-team @org/security-team
/helm/                          @org/platform-team
```

---

### BP-SRC-04: Scan Git History for Secrets Periodically

**Rationale:** Secrets may have been committed to git history months or years before secret scanning was implemented. Pre-existing secrets in git history remain accessible to anyone who clones the repository and could be exploited even if the corresponding configuration no longer references them.

**Implementation:**
```bash
# Run Gitleaks against the full git history
gitleaks detect \
  --source . \
  --verbose \
  --redact \
  --report-format sarif \
  --report-path history-scan.sarif

# Run TruffleHog for high-entropy string detection
trufflehog git \
  file://. \
  --json \
  --no-update \
  > trufflehog-results.json

# Schedule this as a monthly CI job (not just on PR):
# .github/workflows/periodic-secret-scan.yml
on:
  schedule:
    - cron: '0 2 1 * *'  # Monthly on the 1st
```

When secrets are found in git history:
1. Rotate the secret immediately
2. Clean history with `git filter-repo`
3. Force-push cleaned history
4. Notify all collaborators to re-clone

---

### BP-SRC-05: Implement Pre-Commit Hooks as a Developer Safety Net

**Rationale:** Pre-commit hooks run before code enters version control, providing the fastest possible feedback loop. Catching a secret or vulnerable dependency in the developer's local environment is far less disruptive than catching it in a CI pipeline or, worse, after it has been committed to history.

**Implementation:**
```yaml
# .pre-commit-config.yaml
repos:
  # Secret detection
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.4
    hooks:
      - id: gitleaks

  # Basic security checks
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.5.0
    hooks:
      - id: detect-private-key
      - id: check-added-large-files
        args: ['--maxkb=2000']
      - id: no-commit-to-branch
        args: ['--branch', 'main', '--branch', 'master', '--branch', 'release']

  # Python security
  - repo: https://github.com/PyCQA/bandit
    rev: 1.7.7
    hooks:
      - id: bandit
        args: ['-ll']  # Only fail on HIGH severity
        types: [python]

  # Node.js security
  - repo: local
    hooks:
      - id: npm-audit
        name: npm audit
        entry: npm audit --audit-level=high
        language: node
        pass_filenames: false
        always_run: true
```

---

## Build Security

### BP-BLD-01: Use Hermetic Builds with All Dependencies Resolved Before Build

**Rationale:** Builds that download dependencies at build time are subject to:
- Dependency availability outages that break builds
- Dependency substitution attacks (malicious package published to override a legitimate one)
- Version drift over time as "latest" resolves to different packages
Hermetic builds that resolve all dependencies before the build begins are reproducible, auditable, and resistant to supply chain attacks.

**Implementation:**
- Use lock files (package-lock.json, requirements.txt with pinned versions, go.sum, Cargo.lock) and commit them
- Configure package managers to use lock files exclusively in CI: `npm ci`, `pip install -r requirements.txt --require-hashes`
- Use a private package proxy (JFrog Artifactory, Nexus, Google Artifact Registry) to mirror external packages
- Vendor all dependencies for high-security projects (`npm pack`, `go mod vendor`, `pip download`)
- Configure package managers to fail on unauthenticated downloads from public registries when a private mirror exists

---

### BP-BLD-02: Run Each Build Job with Minimal Required Permissions

**Rationale:** CI/CD build jobs accumulate permissions over time as new integrations are added. A build job that has permissions to read source code, write to all registries, deploy to all environments, and manage cloud resources provides an attacker with enormous leverage if the build environment is compromised.

**Implementation:**
- Audit all CI/CD jobs and document the permissions each actually requires
- For GitHub Actions: declare explicit `permissions:` blocks at the job level
  ```yaml
  jobs:
    build:
      permissions:
        contents: read      # Read source code
        packages: write     # Push to GHCR
        security-events: write  # Upload SARIF
        # id-token: write  # Only if using OIDC
  ```
- Create separate service accounts or OIDC role assumptions for each pipeline stage
- Revoke permissions that cannot be explicitly justified

---

### BP-BLD-03: Validate Build Tool Integrity

**Rationale:** If a build tool (Maven, pip, npm, Docker) is itself compromised or substituted, all artifacts built with it are potentially malicious. Build tool integrity validation ensures that the tools used to build software are authentic and unmodified.

**Implementation:**
- Pin build tool container images to digest, not just version tags
- Verify checksums for build tool binaries downloaded at build time
  ```bash
  # Verify downloaded tool checksum before use
  curl -Lo /usr/local/bin/gitleaks \
    https://github.com/gitleaks/gitleaks/releases/download/v8.18.4/gitleaks_8.18.4_linux_x64
  echo "expected-sha256-hash  /usr/local/bin/gitleaks" | sha256sum -c
  chmod +x /usr/local/bin/gitleaks
  ```
- Use verified, official base images from trusted registries
- Maintain an internal mirror of approved build tool images; use only internal images in production builds

---

### BP-BLD-04: Generate Build Provenance Attestations

**Rationale:** Build provenance provides a verifiable record of how a software artifact was produced — which source code it was built from, which build system was used, and which inputs were consumed. Provenance enables consumers of artifacts to verify supply chain integrity and detect unauthorized build modifications.

**Implementation:**
```yaml
# GitHub Actions: SLSA provenance generation
- name: Generate SLSA provenance
  uses: slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@v1.10.0
  with:
    image: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}
    digest: ${{ steps.build.outputs.digest }}
    registry-username: ${{ github.actor }}
    registry-password: ${{ secrets.GITHUB_TOKEN }}
```

This generates SLSA Level 3 provenance, attestating that:
- The build ran on GitHub's infrastructure
- The build configuration came from version control
- The provenance is signed by GitHub's OIDC identity

---

## Test Security

### BP-TST-01: Run DAST Against Every Staging Deployment

**Rationale:** DAST tests a running application and can detect vulnerabilities that are invisible in static analysis: authentication bypass, session management flaws, business logic vulnerabilities, and runtime configuration issues. Running DAST against every staging deployment ensures no release reaches production without dynamic security validation.

**Implementation:**
```yaml
# OWASP ZAP baseline scan (fast, ~5 minutes)
- name: ZAP Baseline Scan
  uses: zaproxy/action-baseline@v0.10.0
  with:
    target: 'https://staging.myapp.example.com'
    rules_file_name: '.zap/rules.tsv'
    allow_issue_writing: true
    fail_action: true  # Block if high findings present

# For release candidates: Full scan
- name: ZAP Full Scan
  if: startsWith(github.ref, 'refs/tags/')
  uses: zaproxy/action-full-scan@v0.10.0
  with:
    target: 'https://staging.myapp.example.com'
    fail_action: true
```

---

### BP-TST-02: Include Security Regression Tests in the Test Suite

**Rationale:** Vulnerabilities that have been fixed can be reintroduced through code refactoring, dependency updates, or merge conflicts. Security regression tests — automated tests that verify specific vulnerabilities are not present — prevent reintroduction and provide fast feedback when a fix is accidentally reverted.

**Implementation:**
- For every Critical/High vulnerability fixed: write a regression test that reproduces the vulnerable condition and verifies the fix
- Include authentication and authorization tests in the functional test suite
- Test boundary conditions for all input validation logic
- Run security regression tests as part of the standard test suite — not as a separate security-only step

```python
# Example: SQL injection regression test
def test_no_sql_injection_in_user_search():
    """Regression test: CVE-2023-XXXX - SQL injection in user search endpoint"""
    response = client.get(
        "/api/users",
        params={"name": "'; DROP TABLE users; --"}
    )
    # Should return empty results or validation error, not execute SQL
    assert response.status_code in [200, 400]
    assert "DROP TABLE" not in str(response.content)
    # Verify no database error returned
    assert "syntax error" not in response.text.lower()
```

---

### BP-TST-03: Include Authentication and Authorization Tests in Every Pipeline

**Rationale:** Authentication and authorization failures are consistently in the OWASP Top 10 and are among the most impactful vulnerability classes. Testing that access controls work correctly — including negative tests verifying that unauthenticated and unauthorized requests are rejected — should be automated and run on every deployment.

**Implementation:**
- Test every authenticated endpoint for: unauthenticated access (should be rejected), access with valid but unauthorized credentials (should be rejected with 403), access with valid authorized credentials (should succeed)
- Test horizontal privilege escalation: user A cannot access user B's resources
- Test vertical privilege escalation: regular users cannot access admin endpoints
- Use a testing framework that makes these patterns easy: pytest with fixtures, Jest with beforeEach, or JUnit with test utilities

---

## Deployment Security

### BP-DEP-01: Require Human Approval for Production Deployments

**Rationale:** Fully automated continuous deployment to production eliminates the human review step that can catch last-minute configuration errors, security issues that passed automated tests, or business-context problems that automated tools cannot detect. A mandatory approval step for production deployments adds a final sanity check.

**Implementation:**
- In GitHub Actions: use Environments with required reviewers
  ```yaml
  jobs:
    deploy-production:
      environment:
        name: production  # This environment requires reviewer approval
      # ...
  ```
- Define which personnel are authorized production approvers: Release Engineers, Engineering Managers, or on-call engineers
- Integrate with change management systems (ServiceNow, Jira Service Management) for regulated deployments
- Exception for hot-fix deployments: define an expedited approval process that is fast but auditable

---

### BP-DEP-02: Use Progressive Delivery to Limit Blast Radius

**Rationale:** Deploying a change to 100% of users simultaneously maximizes the blast radius of any issue — security or functional — that slips through testing. Progressive delivery strategies (canary, blue/green) limit exposure during rollout and provide automated rollback triggers.

**Implementation:**
```yaml
# Argo Rollouts: Canary with automated analysis
spec:
  strategy:
    canary:
      analysis:
        startingStep: 1
        templates:
          - templateName: error-rate-check
        args:
          - name: service-name
            value: myapp-canary
      steps:
        - setWeight: 5
        - pause: {duration: 10m}
        - setWeight: 25
        - pause: {duration: 10m}
        - setWeight: 100
---
apiVersion: argoproj.io/v1alpha1
kind: AnalysisTemplate
metadata:
  name: error-rate-check
spec:
  metrics:
    - name: error-rate
      successCondition: result[0] < 0.05  # < 5% error rate
      interval: 2m
      provider:
        prometheus:
          address: http://prometheus:9090
          query: |
            sum(rate(http_requests_total{status=~"5..",service="{{args.service-name}}"}[2m]))
            /
            sum(rate(http_requests_total{service="{{args.service-name}}"}[2m]))
```

---

### BP-DEP-03: Verify Artifact Integrity Before Every Deployment

**Rationale:** The security controls applied during the build phase are only effective if the artifact deployed to production is the same artifact that passed those controls. An attacker who substitutes a malicious artifact after the build but before deployment can bypass all CI security gates. Artifact signature verification before deployment closes this gap.

**Implementation:**
```yaml
# Kyverno policy: Require Cosign signature for all production deployments
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: verify-image-signature
spec:
  validationFailureAction: Enforce
  background: false
  rules:
    - name: check-signature
      match:
        any:
          - resources:
              kinds: [Pod]
              namespaces: [production, staging]
      verifyImages:
        - imageReferences: ["ghcr.io/myorg/*"]
          attestors:
            - count: 1
              entries:
                - keyless:
                    subject: "https://github.com/myorg/myrepo/.github/workflows/release.yml@refs/heads/main"
                    issuer: "https://token.actions.githubusercontent.com"
```

---

## Secrets Management

### BP-SEC-01: Never Store Secrets in Container Images

**Rationale:** Container images are widely distributed and often stored in registries with broad read access. Secrets embedded in image layers — even intermediate layers — are accessible to anyone who can pull the image. Image layers persist in the image history even after the `RUN` command that wrote them has been overwritten.

**Implementation:**
```dockerfile
# INSECURE: Secret copied into image layer
COPY .env /app/.env  # .env file with secrets is now in image layer

# INSECURE: Secret passed as build ARG (visible in docker history)
ARG DATABASE_URL
RUN echo $DATABASE_URL > /app/config.env

# SECURE: Inject secrets at runtime using Vault Agent or environment variables
# The Dockerfile contains no secrets whatsoever
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY src/ ./src/
USER nonroot
ENTRYPOINT ["python", "-m", "uvicorn", "src.main:app"]
# Secrets are injected at pod startup by Vault Agent or passed as env vars by the orchestrator
```

---

### BP-SEC-02: Rotate Secrets Automatically and on Suspicion of Compromise

**Rationale:** Secrets that are never rotated have an indefinite exposure window. A secret that was exposed in a breach years ago and never rotated remains useful to an attacker today. Automatic rotation at defined intervals combined with immediate rotation on suspected compromise minimizes exposure windows.

**Implementation:**
- Implement HashiCorp Vault dynamic secrets for database credentials: each application request generates a new credential with a short TTL
- Use AWS Secrets Manager rotation with Lambda functions for credentials that cannot be made dynamic
- Implement automated alerts for secrets approaching their maximum TTL
- Document and test the emergency secret rotation procedure quarterly
- Define "suspicion criteria" that trigger immediate rotation: any security scan detecting the secret in logs or code, any unplanned access from an unexpected source, any personnel departure with access to the secret

---

### BP-SEC-03: Use Separate Secrets for Each Environment

**Rationale:** If the same database credentials are used in development, staging, and production, a compromise of the development environment — which typically has weaker security controls — provides direct access to production databases. Environment isolation for secrets is a fundamental principle of defense in depth.

**Implementation:**
- Maintain separate Vault namespaces or secret paths for each environment: `secret/dev/myapp`, `secret/staging/myapp`, `secret/production/myapp`
- Create separate database users for each environment with access only to that environment's database
- Use separate AWS accounts/GCP projects/Azure subscriptions per environment
- Verify environment isolation by attempting to use a staging credential against the production database — it should fail
- Audit secret access patterns to detect anomalous cross-environment access

---

## Access Control

### BP-ACC-01: Implement Just-in-Time (JIT) Access for Elevated Pipeline Permissions

**Rationale:** Standing (always-on) privileged access to production pipelines and deployment systems creates unnecessary risk. Engineers with standing production access can inadvertently or maliciously make unauthorized changes. JIT access grants elevated permissions only when needed, for a defined duration, with full audit trail.

**Implementation:**
- Use HashiCorp Boundary, AWS IAM Identity Center, or similar tools to provide JIT access to production systems
- Define access workflows: engineer requests access, manager approves, access is granted for 4 hours, all actions are logged
- Remove the ability for individual engineers to deploy to production directly; require the CD pipeline with approval gates
- Audit all direct production access events; alert on access outside of approved change windows

---

### BP-ACC-02: Enforce Multi-Factor Authentication for All CI/CD Platform Access

**Rationale:** CI/CD platforms have access to source code, secrets, deployment targets, and cloud environments. A compromised CI/CD platform account provides an attacker with extraordinary leverage. MFA significantly raises the bar for account compromise.

**Implementation:**
- Enforce MFA at the identity provider level for all users with CI/CD platform access
- Require hardware security keys (FIDO2/WebAuthn, YubiKey) for privileged accounts (CI/CD administrators, release engineers)
- Implement Conditional Access policies: block CI/CD access from untrusted locations or devices
- Audit MFA enrollment status quarterly; off-board any accounts not enrolled in MFA

---

### BP-ACC-03: Audit CI/CD Access Controls on a Regular Cadence

**Rationale:** Access control lists accumulate cruft over time: former employees whose accounts were not fully deprovisioned, service accounts with permissions that were granted for a one-time task, and over-broad permissions granted for convenience that were never narrowed. Regular access audits identify and remove this accumulated risk.

**Implementation:**
- Conduct a CI/CD access audit at minimum quarterly, covering: repository access levels, pipeline trigger permissions, production deployment approver lists, secrets access policies, and cloud resource permissions
- Use automated tooling to generate access reports (GitHub access exports, AWS IAM Access Analyzer, Vault audit reports)
- Flag accounts that have not been used in 90+ days for review
- Immediately revoke access on employee departure via automated deprovisioning integration with HR systems

---

## Audit and Compliance

### BP-AUD-01: Maintain Immutable Audit Logs for All Pipeline Activity

**Rationale:** During a security incident, audit logs are the primary evidence source for understanding what happened, when it happened, and who caused it. Logs that can be modified or deleted by an attacker are worse than useless — they create false confidence and may hide evidence of the breach.

**Implementation:**
- Forward all CI/CD platform audit events to an immutable log store (AWS CloudTrail with S3 Object Lock, Azure Immutable Storage, Worm-protected log storage)
- Configure log shipping to be authenticated and encrypted; verify log integrity with CloudTrail log file validation
- Retain pipeline audit logs for a minimum of 365 days; longer for regulated industries (PCI-DSS: 1 year online, 1 year offline)
- Grant read-only access to audit logs for investigators; no one should be able to delete or modify logs

---

### BP-AUD-02: Map Pipeline Controls to Compliance Frameworks

**Rationale:** Audit preparation is expensive and disruptive when it requires manually gathering evidence across many systems. Organizations that pre-map their CI/CD security controls to compliance requirements and automate evidence collection can satisfy auditors efficiently and continuously rather than scrambling at audit time.

**Implementation:**
- Document how each CI/CD security control maps to SOC 2 Common Criteria, PCI-DSS requirements, or other applicable frameworks
- Automate evidence collection: SAST scan reports, deployment approval records, access review logs, vulnerability remediation evidence — all available on demand from centralized systems
- Use compliance-as-code tools (Chef InSpec, AWS Config Rules, Wiz compliance policies) to continuously validate controls
- Conduct an internal pre-audit annually — simulate an auditor's evidence requests and verify that evidence can be produced within 24 hours

---

### BP-AUD-03: Generate and Maintain SBOMs for All Production Artifacts

**Rationale:** When a new CVE is disclosed (e.g., a critical vulnerability in a popular library), organizations need to quickly determine whether they are affected. Without SBOMs, determining which deployed systems include a vulnerable component requires manual investigation across many repositories and build systems. SBOMs enable instant impact analysis.

**Implementation:**
- Generate SBOMs in both SPDX and CycloneDX formats for every build artifact
- Attach SBOMs as provenance attestations to container images using Cosign
- Store SBOMs in a queryable SBOM repository (dependency-track, Anchore Enterprise)
- Automate CVE scanning against SBOMs: when a new critical CVE is published, automatically query all SBOMs to identify affected artifacts
- Include SBOMs in vendor security attestations required by US Executive Order 14028 and enterprise customer contracts

---

### BP-AUD-04: Automate Compliance Evidence Collection

**Rationale:** Manually gathering evidence for SOC 2, PCI-DSS, or ISO 27001 audits is time-consuming and error-prone. Automation ensures evidence is consistently collected, accurately reflects the current state of controls, and is available on demand rather than requiring weeks of preparation.

**Implementation:**
```yaml
# Example: Automated evidence collection workflow
# Runs monthly to collect compliance evidence artifacts

name: Compliance Evidence Collection
on:
  schedule:
    - cron: '0 6 1 * *'  # First of each month

jobs:
  collect-evidence:
    runs-on: ubuntu-latest
    steps:
      - name: Export SAST scan results
        # Pull last 30 days of scan results from security platform
        run: |
          snyk report --org=$ORG_ID --format=json \
            --from=$(date -d '30 days ago' +%Y-%m-%d) \
            > sast-evidence-$(date +%Y-%m).json

      - name: Export deployment approval records
        # Pull deployment approval events from CD platform
        run: |
          gh api /repos/$GITHUB_REPOSITORY/deployments \
            --paginate \
            --jq '[.[] | select(.environment == "production")]' \
            > deployment-approvals-$(date +%Y-%m).json

      - name: Export access review report
        run: |
          # Automated access report generation
          python scripts/generate-access-report.py > access-report-$(date +%Y-%m).json

      - name: Upload to compliance evidence store
        run: |
          aws s3 cp *.json s3://compliance-evidence-store/$(date +%Y/%m)/
```
