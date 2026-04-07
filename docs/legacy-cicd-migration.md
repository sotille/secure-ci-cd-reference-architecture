# Migrating Legacy CI/CD Platforms to Secure Pipeline Architecture

Many organizations operate CI/CD infrastructure built on platforms designed in an era before supply chain attacks, pipeline injection, and build system compromise were recognized threats. Jenkins instances running as root with unrestricted internet access, Bamboo configurations with shared credentials in plaintext, and TeamCity build agents with persistent home directories are common in organizations that haven't revisited their CI/CD security posture in several years.

This guide provides a structured migration approach for moving from legacy CI/CD platforms to the secure pipeline architecture defined in the [Techstream Secure CI/CD Reference Architecture](architecture.md), with specific guidance for the most common legacy platforms: Jenkins, Bamboo, and TeamCity.

---

## Table of Contents

- [Migration Assessment](#migration-assessment)
- [Migration Strategy Options](#migration-strategy-options)
- [Platform-Specific Migration Guides](#platform-specific-migration-guides)
- [Security Hardening During Migration](#security-hardening-during-migration)
- [Pipeline Pattern Mapping](#pipeline-pattern-mapping)
- [Secrets Migration](#secrets-migration)
- [Risk Management During Migration](#risk-management-during-migration)
- [Validation and Cutover](#validation-and-cutover)
- [Post-Migration Security Baseline](#post-migration-security-baseline)

---

## Migration Assessment

Before committing to a migration strategy, conduct a structured assessment of the legacy environment. The scope and risk of migration depends heavily on what has accumulated in the existing platform.

### Legacy Platform Inventory

**For each CI/CD platform instance, document:**

| Item | Why It Matters |
|---|---|
| Number of active pipelines/jobs | Migration scope and effort |
| Number of inactive pipelines | Opportunity to eliminate technical debt |
| Shared vs. dedicated build agents | Blast radius assessment; shared agents are a high-risk pattern |
| Stored credentials and secrets | Migration complexity; most dangerous assets |
| External integrations (Jira, Slack, Artifact repositories) | Integration re-establishment effort |
| Custom plugins/extensions | Compatibility risk; plugin versions are often a security debt |
| Pipeline authors (active vs. departed employees) | Knowledge transfer requirements |
| Job execution frequency | Priority for migration; high-frequency jobs have more business impact |
| Artifact dependencies (what artifacts does this platform produce?) | Downstream dependency mapping |

### Security Debt Assessment

Run a security assessment of the legacy platform before migrating. This establishes the baseline against which migration security improvement is measured, and surfaces critical issues that need interim mitigation even if full migration takes months.

**Common legacy CI/CD security findings:**

| Finding | Severity | Interim Mitigation |
|---|---|---|
| Build agents running as root/SYSTEM | Critical | Add sudo rules to restrict; prioritize this for migration |
| Credentials in build scripts (plaintext) | Critical | Move to credential store immediately; don't wait for migration |
| No network egress restrictions on build agents | High | Add egress filtering at network level as interim control |
| Shared build agents with credential persistence | High | Agent workspace cleanup between jobs; prioritize dedicated agents |
| Admin access to CI/CD platform for all developers | High | Implement RBAC on legacy platform immediately |
| No build artifact signing | Medium | Add signing if the legacy platform supports it |
| No SBOM generation | Medium | Add SBOM generation as a job step; can migrate artifacts to new platform |
| Plugin versions not pinned | Medium | Document installed plugin versions; create remediation plan |
| No audit logging | High | Enable if available; export to SIEM |
| Public-facing legacy CI/CD UI | High | Move behind VPN/private network or add WAF immediately |

---

## Migration Strategy Options

### Option 1: Big-Bang Migration

Replace the legacy platform entirely within a defined migration window.

**Suitable for:**
- Organizations with fewer than 50 active pipelines
- Teams with dedicated platform engineering capacity
- Organizations with a hard regulatory or contractual deadline

**Risks:**
- High coordination overhead
- Difficult rollback if migration encounters problems
- Business continuity risk during the migration window

### Option 2: Strangler Fig Migration (Recommended)

Migrate pipelines incrementally to the new platform while the legacy platform continues operating. New repositories and new pipelines start on the new platform; existing pipelines migrate on a rolling schedule.

**Suitable for:**
- Most organizations (50–500+ pipelines)
- Organizations where business continuity is a primary constraint
- Teams with limited migration bandwidth

**Process:**
1. New platform deployed and validated with pilot pipelines (Month 1)
2. All new projects start on new platform (Month 1 onwards)
3. High-security-risk pipelines migrated (Month 2–3)
4. Remaining pipelines migrated on team schedule (Month 4–12)
5. Legacy platform decommissioned after migration completion

### Option 3: Security Hardening of Legacy Platform (Interim Only)

When full migration is not possible within the required timeframe, harden the legacy platform as an interim measure while planning a full migration.

This is not a permanent solution. Legacy platforms accumulate security debt faster than they can be hardened against new threat patterns. Set a firm decommission date and hold to it.

---

## Platform-Specific Migration Guides

### Migrating from Jenkins

Jenkins is the most commonly deployed legacy CI/CD platform and carries the highest security debt due to its plugin ecosystem, which has a long history of security vulnerabilities and inconsistent maintenance.

**Key Jenkins security risks to address before migration:**
- Jenkins built-in user database (migrate to SSO/OIDC)
- Script Security plugin bypasses (common in Scripted Pipelines using `@Grab` or reflection)
- Credential binding to build output (credentials may be in build logs)
- Shared library code execution without security review
- Jenkins agents with `JNLP` web-based connectivity (replace with outbound-only WebSocket or SSH agents)

**Jenkins to GitHub Actions migration mapping:**

| Jenkins Concept | GitHub Actions Equivalent |
|---|---|
| `Jenkinsfile` | `.github/workflows/*.yml` |
| Scripted Pipeline (Groovy) | Workflow steps with shell or composite actions |
| Shared Libraries | Reusable workflows + composite actions |
| Jenkins Credentials Store | GitHub Secrets (repository or environment) |
| Build Agents | Runners (GitHub-hosted or self-hosted) |
| Jenkins Plugins | Actions from GitHub Marketplace |
| Post-build actions | `if: always()` steps in workflow jobs |
| Parameterized builds | `workflow_dispatch` inputs |
| Jenkins Views / Folders | GitHub Teams, repositories, environments |
| Jenkins Pipeline stages | Jobs within a workflow |

**Jenkins to GitHub Actions migration example:**

```groovy
// Legacy Jenkins Scripted Pipeline
pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                sh 'mvn clean package -DskipTests'
            }
        }
        stage('Test') {
            steps {
                sh 'mvn test'
                junit 'target/surefire-reports/**/*.xml'
            }
        }
        stage('Deploy') {
            when { branch 'main' }
            steps {
                withCredentials([string(credentialsId: 'deploy-key', variable: 'DEPLOY_KEY')]) {
                    sh './deploy.sh $DEPLOY_KEY'
                }
            }
        }
    }
}
```

```yaml
# Equivalent GitHub Actions workflow (secure)
name: Build and Deploy

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  contents: read
  id-token: write  # Required for OIDC cloud auth

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4

    - name: Set up Java
      uses: actions/setup-java@v4
      with:
        java-version: '21'
        distribution: 'temurin'
        cache: 'maven'

    - name: Build
      run: mvn clean package -DskipTests

    - name: Test
      run: mvn test

    - name: Upload test results
      if: always()
      uses: actions/upload-artifact@v4
      with:
        name: test-results
        path: target/surefire-reports/

  deploy:
    needs: build
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    environment: production    # Requires manual approval (GitHub environment protection)
    steps:
    - uses: actions/checkout@v4

    # OIDC auth instead of stored credentials
    - name: Configure AWS credentials
      uses: aws-actions/configure-aws-credentials@v4
      with:
        role-to-assume: arn:aws:iam::123456789012:role/github-actions-deploy
        aws-region: us-east-1

    - name: Deploy
      run: ./deploy.sh  # No credential passed in env — uses OIDC session
```

### Migrating from Atlassian Bamboo

Bamboo's primary challenge is its tight integration with the Atlassian ecosystem (Jira, Bitbucket Server). Organizations migrating Bamboo typically also consider migrating from Bitbucket Server to Bitbucket Cloud or GitHub.

**Bamboo to GitHub Actions or GitLab CI mapping:**

| Bamboo Concept | GitHub Actions | GitLab CI |
|---|---|---|
| Build Plan | Workflow file | `.gitlab-ci.yml` pipeline |
| Build Stage | Job | Stage |
| Build Task | Step | Job (in stage) |
| Bamboo Variables | GitHub Secrets / Variables | GitLab CI/CD Variables |
| Shared Credentials | GitHub Secrets (org-level) | GitLab Group Variables |
| Bamboo Specs (YAML) | Workflow YAML (native) | `.gitlab-ci.yml` (native) |
| Plan Branches | Branch-based workflows | Branch pipelines |
| Deployments | GitHub Environments | GitLab Environments |
| Bamboo Agents | GitHub Runners / GitLab Runners | GitLab Runners |

**Bamboo-specific migration considerations:**

1. **Bamboo Specs migration** — if Bamboo Specs (YAML-based plan definitions) were used, they can be converted to GitHub Actions or GitLab CI with lower friction than Bamboo Java plan definitions.

2. **Bamboo Permissions** — Bamboo's plan-level permissions must be re-implemented as GitHub team permissions or GitLab project access levels. Map existing permissions before migration.

3. **Jira integration** — Bamboo's native Jira integration (deployment tracking, issue linking) can be replicated with GitHub Actions Jira integration or GitLab's Jira integration. Deployment events become GitHub deployment events.

4. **Artifact management** — Bamboo's artifact sharing between stages (plan artifacts) maps to GitHub Actions artifacts or GitLab job artifacts.

### Migrating from JetBrains TeamCity

TeamCity's primary security risk areas are its build agent trust model (build agents can access the TeamCity server API with broad permissions) and its reliance on stored credentials in the TeamCity credential store (accessible to anyone with build configuration access).

**TeamCity to GitHub Actions mapping:**

| TeamCity Concept | GitHub Actions Equivalent |
|---|---|
| Build Configuration | Workflow file |
| Build Steps | Steps within a job |
| Build Features | GitHub Actions (specific actions for each feature) |
| VCS Roots | Source code checkout (`actions/checkout`) |
| TeamCity Parameters | GitHub Secrets / Variables / Inputs |
| Connection (credential) | GitHub Secrets |
| Build Agents | Runners |
| Build Chain | Workflow dependencies (`needs:`) |
| Project / Sub-Project | GitHub Organization / Repository / Team |
| Templates | Reusable workflows |
| Meta-Runners | Composite actions |

**TeamCity-specific migration considerations:**

1. **Build chains** — TeamCity's build chain feature (where builds trigger other builds and artifacts flow downstream) maps to GitHub Actions `workflow_dispatch` triggers and artifact passing between workflows.

2. **TeamCity DSL (Kotlin)** — organizations using TeamCity's Kotlin DSL for configuration-as-code can export existing configurations and use them as the basis for GitHub Actions or GitLab CI YAML generation.

3. **TeamCity test intelligence** — TeamCity's test history, flaky test detection, and test parallelization features must be replicated with GitHub Actions test reporting actions or GitLab's test summary features.

---

## Security Hardening During Migration

### Zero-Trust Build Agent Design

The new platform's build agents must be designed on a zero-trust model from the start:

```yaml
# Self-hosted runner: minimal permissions, ephemeral execution
# Deploy runners as Kubernetes Jobs (ephemeral) rather than long-running pods
apiVersion: batch/v1
kind: Job
metadata:
  name: github-actions-runner
  namespace: ci-runners
spec:
  ttlSecondsAfterFinished: 300
  template:
    spec:
      serviceAccountName: ci-runner   # Minimal RBAC — no cluster-admin
      automountServiceAccountToken: false  # Opt-in only
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
        seccompProfile:
          type: RuntimeDefault
      containers:
      - name: runner
        image: ghcr.io/actions/actions-runner:latest
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: false   # Runner needs writable filesystem
          capabilities:
            drop: [ALL]
        resources:
          limits:
            memory: "4Gi"
            cpu: "2"
          requests:
            memory: "2Gi"
            cpu: "1"
      restartPolicy: Never
```

### Network Egress Controls

Legacy CI/CD agents typically have unrestricted internet access. New agents must be restricted to necessary egress only:

```hcl
# Terraform: security group for CI/CD runners with restricted egress
resource "aws_security_group" "ci_runners" {
  name        = "ci-cd-runners"
  description = "Security group for CI/CD build runners"
  vpc_id      = var.vpc_id

  # Allow outbound HTTPS to required destinations only
  egress {
    description = "HTTPS to GitHub (source control + Actions)"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    prefix_list_ids = [aws_ec2_managed_prefix_list.github.id]
  }

  egress {
    description = "HTTPS to internal artifact registry"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.artifact_registry_cidr]
  }

  egress {
    description = "DNS"
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = ["${var.vpc_dns_server}/32"]
  }

  tags = {
    "techstream:function" = "security"
    "techstream:security-domain" = "network-security"
  }
}
```

---

## Pipeline Pattern Mapping

### Migrating Shared Libraries (Jenkins) to Reusable Workflows

Jenkins Shared Libraries are the most common source of implicit trust in Jenkins environments — code executed in shared libraries often bypasses Script Security restrictions and can access sensitive Jenkins credentials.

**Migration approach:**

1. Audit all shared library usage across pipelines
2. Categorize shared library functions: utility (safe to migrate), credential-handling (security-sensitive), infrastructure interaction (high-risk)
3. Implement credential-handling functions as dedicated, reviewed GitHub Actions or GitLab CI templates
4. Implement utility functions as composite actions with explicit input/output contracts

```yaml
# GitHub Actions reusable workflow: equivalent of Jenkins shared library
# .github/workflows/security-scan.yml
name: Security Scan (Reusable)

on:
  workflow_call:
    inputs:
      image-ref:
        required: true
        type: string
      severity-threshold:
        required: false
        type: string
        default: HIGH
    outputs:
      scan-result:
        description: Scan result (pass/fail)
        value: ${{ jobs.scan.outputs.result }}
    secrets:
      registry-token:
        required: true

jobs:
  scan:
    runs-on: ubuntu-latest
    outputs:
      result: ${{ steps.scan.outputs.result }}
    steps:
    - name: Scan container image
      id: scan
      uses: aquasecurity/trivy-action@0.24.0
      with:
        image-ref: ${{ inputs.image-ref }}
        severity: ${{ inputs.severity-threshold }},CRITICAL
        exit-code: '1'
```

---

## Secrets Migration

Migrating secrets from a legacy CI/CD credential store is the highest-risk phase of the migration. Secrets must be:

1. **Inventoried** — document every secret in the legacy store before migration
2. **Classified** — assign tier (see [Secret Lifecycle Management](../../devsecops-framework/docs/secret-lifecycle-management.md)) and identify owners
3. **Tested** — verify each secret is still valid before migrating (many will be stale or unused)
4. **Rotated before migration** — do not copy old credentials to the new platform; generate new credentials and migrate them
5. **Revoked in the legacy store** — after confirming the new credential works in the new platform, revoke the legacy copy

### Secrets Migration Checklist

For each credential in the legacy store:

- [ ] Identify consuming pipelines (run a grep/search across all pipeline configurations)
- [ ] Identify the human or service that owns the credential
- [ ] Verify the credential is still valid (if uncertain, test against the target system)
- [ ] Determine if the credential can be replaced with OIDC workload identity (preferred)
- [ ] If OIDC is not available: generate a new credential; do not reuse the legacy credential
- [ ] Configure the new credential in the new platform's secrets store
- [ ] Update all consuming pipelines in the new platform to use the new credential
- [ ] Run a test pipeline run in the new platform to verify the credential works
- [ ] Revoke the legacy credential in the legacy store (and in the target system)
- [ ] Document the new credential in the secrets inventory

---

## Risk Management During Migration

### Dual-Running Risk

During the strangler fig migration, both platforms run simultaneously and may produce artifacts from the same codebase. This creates risks:

1. **Inconsistent security controls** — legacy platform may have weaker scanning; ensure downstream systems use artifacts from the new (secure) platform only
2. **Credential duplication** — both platforms may hold credentials for the same target systems; minimize duplication and track in the secrets inventory
3. **Audit trail fragmentation** — deployment evidence split between two platforms; ensure the evidence store collects from both during the transition period

### Rollback Criteria

Define explicit criteria under which a pipeline migration will be rolled back to the legacy platform:

- New platform produces build failures not present in legacy (non-security-related)
- Deployment time increases > 50% due to new platform overhead
- New security gates create a blocking false positive rate > 10%
- New platform outage affecting delivery (acceptable; migrate back and investigate)

---

## Validation and Cutover

### Pre-Cutover Validation Checklist

Before declaring a migrated pipeline production-ready on the new platform:

**Security:**
- [ ] All security gates passing (SAST, SCA, secrets, container scan, IaC scan)
- [ ] Build artifacts signed with Cosign
- [ ] SBOM generated and uploaded to Dependency-Track
- [ ] No credentials stored in plain text in pipeline configuration
- [ ] OIDC workload identity used for cloud authentication (where applicable)
- [ ] Runner network egress restricted to required destinations

**Functionality:**
- [ ] Build and test stages produce identical artifacts as legacy platform (byte-for-byte comparison for reproducible builds, or functional equivalence verification)
- [ ] Deployment stages successfully deploy to staging environment
- [ ] Rollback pipeline tested and confirmed functional

**Governance:**
- [ ] Approval gates configured (environment protection rules for production)
- [ ] Audit logging enabled and flowing to SIEM
- [ ] Deployment evidence flowing to compliance evidence store

### Cutover Process

For each pipeline:

1. Run parallel for two weeks: legacy produces production artifacts; new platform produces validated but non-deployed artifacts
2. Compare outputs (artifact content, test results, scan results)
3. After successful parallel validation: switch production to new platform for one deployment
4. Monitor for 48 hours
5. Decommission legacy pipeline for this service (do not leave it running — it creates confusion)

---

## Post-Migration Security Baseline

After migration, validate that the security baseline described in the [Secure CI/CD Reference Architecture](architecture.md) is fully implemented:

| Security Zone | Verification |
|---|---|
| Developer zone | Pre-commit hooks on all active repos; IDE security plugins deployed |
| Source control zone | Branch protection enabled; required status checks include all security gates |
| CI/CD build zone | Build agents ephemeral; no persistent credentials; network egress restricted |
| Staging zone | Staging environment isolated from production; DAST running post-deployment |
| Production zone | Deployment requires passing all gates; immutable audit trail active |

Legacy CI/CD platforms left running after primary pipelines have migrated are a persistent security risk. Set a firm shutdown date for the legacy platform within 3 months of completing migration. If some pipelines cannot be migrated within 3 months, document them explicitly with a remediation timeline — do not leave the legacy platform running indefinitely for a small number of residual pipelines.

---

## Related Techstream Resources

- [Secure CI/CD Reference Architecture — Architecture](architecture.md)
- [Secure CI/CD Reference Architecture — Threat Model](threat-model.md)
- [Secure CI/CD Reference Architecture — Implementation Guide](implementation.md)
- [Secure Pipeline Templates — GitHub Actions Template](../../secure-pipeline-templates/templates/github-actions-secure-pipeline.yml)
- [Secure Pipeline Templates — IaC Security Pipeline](../../secure-pipeline-templates/templates/iac-security-pipeline.yml)
- [DevSecOps Framework — Secret Lifecycle Management](../../devsecops-framework/docs/secret-lifecycle-management.md)
