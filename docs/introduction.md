# Introduction: Securing CI/CD Pipelines

## Table of Contents

- [Overview of CI/CD Security Challenges](#overview-of-cicd-security-challenges)
- [Threat Model for CI/CD Pipelines: STRIDE Analysis](#threat-model-for-cicd-pipelines-stride-analysis)
- [Attack Vectors in CI/CD Environments](#attack-vectors-in-cicd-environments)
- [CI/CD Attack Tree Analysis](#cicd-attack-tree-analysis)
- [Real-World CI/CD Breach Examples](#real-world-cicd-breach-examples)
- [Why Secure-by-Default Pipelines Matter](#why-secure-by-default-pipelines-matter)
- [Key Concepts](#key-concepts)

---

## Overview of CI/CD Security Challenges

Continuous Integration and Continuous Delivery (CI/CD) pipelines are among the most privileged components in a modern organization's technology stack. A typical CI/CD pipeline holds credentials for source code repositories, cloud provider accounts, container registries, artifact stores, production databases, and third-party services. It can build and deploy arbitrary code to production environments, modify infrastructure configurations, and access secrets across the full technology estate.

This extraordinary level of access makes CI/CD infrastructure a high-value target for adversaries. Yet many organizations secure their CI/CD pipelines as an afterthought, applying significantly weaker controls than they apply to production systems, user identities, or corporate networks. The consequence has been a sustained wave of supply chain compromises, credential theft, and malicious code injection incidents affecting organizations across every industry.

The security challenges specific to CI/CD pipelines include:

### Scale and Complexity of Pipeline Ecosystems

Modern organizations operate dozens or hundreds of pipelines across multiple CI/CD platforms, referencing thousands of third-party actions, plugins, or pipeline libraries. Maintaining security visibility, consistent policy enforcement, and up-to-date dependencies across this ecosystem is operationally challenging.

### Implicit Trust in Pipeline Components

CI/CD pipelines commonly consume external actions, reusable workflows, base Docker images, build tools, and package manager dependencies — all of which execute with the permissions of the pipeline itself. A single compromised upstream dependency can execute arbitrary code within the pipeline's trust boundary, accessing all secrets and credentials available to the pipeline.

### Secrets Proliferation

CI/CD pipelines require access to a large number of credentials to function. These secrets are frequently hardcoded in pipeline configuration files, stored insecurely in environment variables, logged in build output, or shared across pipelines without access controls. Secret sprawl makes credential rotation difficult and creates opportunities for credential theft through pipeline log access.

### Ephemeral Build Environments and Forensic Gaps

Build environments are often destroyed after each job completes. While this limits the persistence of compromises, it also makes forensic investigation difficult following a security incident. Without comprehensive audit logging, it may be impossible to determine whether a compromised build environment affected artifacts that were subsequently deployed.

### Developer Convenience vs. Security Posture

Many CI/CD security weaknesses are introduced in the name of developer convenience. Overly permissive pipeline tokens, disabled branch protection rules, pinned dependency exclusions, and suppressed security gate failures are common examples of security debt that accumulates when velocity is prioritized over security hygiene.

### Supply Chain Attack Surface

The software supply chain — the collection of all tools, dependencies, and services that contribute to software being built and deployed — has become a primary attack surface. Adversaries who can inject malicious code or backdoors into widely-used build tools, package registries, or CI/CD actions can compromise thousands of downstream organizations simultaneously.

---

## Threat Model for CI/CD Pipelines: STRIDE Analysis

The STRIDE threat model (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) provides a structured framework for analyzing CI/CD pipeline threats.

### Spoofing

Spoofing in CI/CD contexts involves an adversary impersonating a legitimate identity — a developer, a service account, or a trusted pipeline component — to gain unauthorized access or introduce malicious changes.

| Threat | Example | Mitigation |
|---|---|---|
| Stolen developer credentials | Attacker uses stolen GitHub token to push malicious commits | MFA enforcement, short-lived tokens, commit signing |
| Service account impersonation | Attacker uses leaked CI service account key to trigger pipelines | OIDC federated identity, least-privilege IAM, token rotation |
| Malicious pipeline action impersonation | Typosquatted GitHub Action mimics a legitimate one | Pin actions to commit SHA, use approved action allowlists |
| Build artifact substitution | Malicious artifact injected in place of legitimate build output | Artifact signing (Sigstore/Cosign), digest verification |

### Tampering

Tampering involves unauthorized modification of source code, pipeline configuration, build artifacts, or dependencies.

| Threat | Example | Mitigation |
|---|---|---|
| Source code modification | Attacker with repository write access injects malicious code | Branch protection, required code review, commit signing |
| Pipeline configuration tampering | Pipeline YAML modified to exfiltrate secrets | Protected branches for pipeline files, change detection alerts |
| Dependency confusion / substitution | Malicious package published with higher version number | Dependency pinning, private package mirrors, SCA scanning |
| Artifact tampering | Build artifact modified after signing | Artifact signing, immutable artifact repositories, digest verification |
| Runner compromise | Compromised self-hosted runner modifies build outputs | Ephemeral runners, runner hardening, network egress controls |

### Repudiation

Repudiation threats arise when actors can deny performing actions due to insufficient logging and audit trails.

| Threat | Example | Mitigation |
|---|---|---|
| Unsigned commits | Developer claims not to have committed malicious code | GPG commit signing enforcement |
| Missing pipeline audit logs | Actions taken during a pipeline run cannot be attributed | Immutable audit logging, pipeline run provenance records |
| Artifact provenance gaps | Cannot prove a deployed artifact came from a specific pipeline run | SLSA provenance attestations, build metadata in artifacts |
| Secret access without attribution | Secrets accessed without recording who accessed them | Vault audit logging, short-lived credentials with identity binding |

### Information Disclosure

Information disclosure threats involve unauthorized exposure of sensitive data — credentials, source code, customer data, or infrastructure configuration.

| Threat | Example | Mitigation |
|---|---|---|
| Secrets in pipeline logs | API key printed to build log by a debug statement | Secret masking, log scrubbing, pre-commit secret scanning |
| Secrets in source code | Hardcoded credentials committed to repository | Pre-commit hooks, SAST secret detection, git history scanning |
| Over-permissive artifact access | Internal build artifacts accessible to unauthorized parties | Artifact repository access controls, signed artifact policies |
| Environment variable leakage | Pipeline environment variables accessible to forked PRs | Fork isolation policies, restricted secret scopes |
| Build cache poisoning / exfiltration | Sensitive data cached and accessible in subsequent builds | Cache isolation per branch/user, cache content scanning |

### Denial of Service

CI/CD pipeline denial of service attacks disrupt the software delivery process.

| Threat | Example | Mitigation |
|---|---|---|
| Pipeline resource exhaustion | Malicious pull request triggers runaway build processes | Concurrency limits, resource quotas, PR author restrictions |
| Build cache corruption | Corrupted cache causes all builds to fail | Cache integrity validation, fallback cache policies |
| Dependency unavailability | Upstream package registry outage blocks all builds | Private package mirrors, vendored dependencies |
| Runner pool exhaustion | Large number of triggered pipelines consume all available runners | Runner autoscaling, job queuing policies, rate limiting |

### Elevation of Privilege

Privilege escalation in CI/CD pipelines involves gaining access or capabilities beyond those authorized.

| Threat | Example | Mitigation |
|---|---|---|
| Over-permissive pipeline tokens | Pipeline token with admin access used to modify repository settings | Least-privilege token scopes, token audit, OIDC |
| Cross-pipeline secret access | Pipeline reads secrets intended for a different pipeline | Namespace-scoped secrets, per-pipeline credentials |
| Runner escape | Malicious build code escapes container sandbox to access host | Rootless containers, gVisor / Kata Containers, ephemeral runners |
| Lateral movement via pipeline | Compromised pipeline used as pivot point to access other systems | Network egress controls, short-lived credentials, network segmentation |

---

## Attack Vectors in CI/CD Environments

### Dependency Confusion and Supply Chain Attacks

Dependency confusion attacks exploit the way package managers resolve package names. When an organization uses private packages hosted on internal registries and a public package with the same name exists (or is created by an attacker) with a higher version number, some package managers preferentially resolve to the public malicious package.

**Attack flow:**
1. Attacker discovers internal package names (via job postings, error messages, or source code)
2. Attacker publishes malicious package to public registry (PyPI, npm, Maven Central) with a higher version
3. Package manager resolves to attacker's package during CI build
4. Malicious code executes within the CI environment with full pipeline permissions

**Documented impact:** In 2021, researcher Alex Birsan demonstrated dependency confusion attacks against Microsoft, Apple, PayPal, and 30+ other major companies, achieving Remote Code Execution in their CI/CD environments.

### Malicious CI/CD Actions and Plugins

GitHub Actions, GitLab CI components, and Jenkins plugins from third-party sources execute arbitrary code within the pipeline's trust boundary. Adversaries can compromise an action maintainer's account or publish malicious actions with names similar to popular legitimate ones.

**Attack flow:**
1. Attacker compromises a popular action's GitHub account via credential theft or supply chain attack
2. Attacker modifies action code to include credential-exfiltrating payload
3. Pipelines using that action automatically execute the malicious code on next run
4. Pipeline secrets exfiltrated to attacker-controlled infrastructure

### Secrets Exfiltration via Pipeline Logs

Build logs are frequently retained in CI/CD systems for debugging purposes and accessed by developers across the organization. If secrets are inadvertently printed to logs — through debug output, environment variable dumps, or tool configuration errors — they can be accessed by anyone with log access.

**Common causes:**
- Debug mode enabled in build tools that dumps environment variables
- API clients that log request headers including Authorization tokens
- Shell scripts using `set -x` that echo commands including secret values
- Error messages that include connection strings with embedded credentials

### Compromised Self-Hosted Runners / Build Agents

Organizations using self-hosted CI/CD runners to access internal resources or reduce costs must secure the runner infrastructure itself. Compromised runners can access all secrets and credentials available to the pipelines they execute, persist across pipeline runs (unlike ephemeral cloud runners), and may have network access to internal systems inaccessible from cloud runners.

### Pull Request Injection (Fork-Based Attacks)

Open-source projects and some enterprise configurations allow external contributors to submit pull requests that trigger CI/CD workflows. If pipelines expose secrets to forked PRs, an attacker can submit a PR with modified pipeline configuration to extract secrets or gain unauthorized infrastructure access.

### Artifact Tampering and Registry Poisoning

If an attacker gains write access to an artifact registry, they can replace legitimate build artifacts with malicious versions. Downstream pipelines or deployments that pull these artifacts without integrity verification will deploy attacker-controlled code.

---

## CI/CD Attack Tree Analysis

Attack trees provide a structured decomposition of attack goals into the specific conditions that must be satisfied for an attack to succeed. The following attack trees cover the two highest-impact goals for CI/CD adversaries: injecting malicious code into a production artifact, and exfiltrating secrets from the pipeline environment.

### Attack Tree 1: Inject Malicious Code into a Production Artifact

```
GOAL: Malicious code in production artifact
│
├── [OR] Compromise the build process
│   ├── [AND] Access to CI/CD platform
│   │   ├── [OR] Stolen developer credentials with CI access
│   │   │   ├── Phishing attack on developer
│   │   │   └── Credential database breach (third-party)
│   │   ├── [OR] Compromised CI service account
│   │   │   ├── Long-lived service account key leaked in code/logs
│   │   │   └── Overpermissioned OIDC token with write scope
│   │   └── [OR] Compromise of CI platform itself (rare)
│   │
│   └── [AND] Ability to modify build outputs
│       ├── Persistent self-hosted runner (survives between jobs)
│       └── Writable artifact store without signing enforcement
│
├── [OR] Compromise a dependency
│   ├── [AND] Malicious package in dependency graph
│   │   ├── [OR] Typosquatting / dependency confusion attack
│   │   │   └── Public package name matches internal package name
│   │   ├── [OR] Compromised upstream package maintainer account
│   │   │   └── Maintainer credentials phished / breached
│   │   └── [OR] Malicious code in new package version
│   │       └── Unpinned dependency auto-updates to attacker version
│   │
│   └── [AND] Malicious package executed at build time
│       └── No dependency hash verification during build
│
├── [OR] Compromise the source code
│   ├── [AND] Unauthorized code commit merged to protected branch
│   │   ├── [OR] Bypass branch protection
│   │   │   ├── Branch protection misconfigured (allows force push)
│   │   │   └── Repository admin account compromised
│   │   └── [OR] Social engineering a code reviewer
│   │       └── Malicious code disguised in large PR / obfuscated logic
│   │
│   └── [AND] Malicious pipeline action executes in build
│       ├── [OR] Mutable action reference changed by attacker
│       │   └── Action referenced by tag (not commit SHA)
│       └── [OR] Malicious action introduced via PR
│           └── Workflow triggered on pull_request from fork
│
└── [OR] Tamper with the artifact after build
    ├── [AND] Access to artifact repository
    │   └── Overpermissive registry access credentials
    │
    └── [AND] No artifact signing / verification at deployment
        └── Deployment system does not verify Cosign signatures
```

**Primary mitigations by attack path:**

| Attack Path | Primary Control | Secondary Control |
|---|---|---|
| Compromised developer credential | MFA enforcement; OIDC workload identity | Short-lived tokens; anomaly detection |
| Malicious dependency | Exact version pinning + hash verification | Private registry mirror; SCA scanning |
| Dependency confusion | Private registry with scope enforcement | Namespace reservation on public registries |
| Mutable action reference | Pin all actions to commit SHA | Action allowlist enforcement |
| Fork PR code execution | Require approval before workflow runs on PRs | Restrict secrets to protected branches |
| Post-build artifact tampering | Cosign signing at build time | Admission control verifying signatures at deploy |

---

### Attack Tree 2: Exfiltrate Secrets from CI/CD Pipeline

```
GOAL: Exfiltrate pipeline secrets (cloud credentials, API keys, signing keys)
│
├── [OR] Read secrets from pipeline logs
│   ├── [AND] Secrets printed to logs
│   │   ├── [OR] Debug logging enabled (set -x, verbose mode)
│   │   ├── [OR] Error output includes secret values
│   │   └── [OR] Tool logs request headers with auth tokens
│   │
│   └── [AND] Log access available to attacker
│       ├── Compromised developer account with log access
│       └── Public repository with publicly visible workflow logs
│
├── [OR] Read secrets from build environment directly
│   ├── [AND] Code execution in CI environment (via any path above)
│   │
│   └── [AND] Secrets available in environment
│       ├── [OR] Secrets in environment variables
│       │   └── No runtime secret injection (pull at use time)
│       └── [OR] Secrets accessible via IMDS/metadata service
│           └── No IMDS hop limit or IP tables block on runners
│
├── [OR] Extract secrets from repository
│   ├── [AND] Secrets committed to repository history
│   │   └── No pre-commit secret scanning with push protection
│   │
│   └── [AND] Read access to repository
│       └── Compromised account or overpermissive token
│
└── [OR] Exfiltrate via pipeline network egress
    ├── [AND] Secret access achieved (any above path)
    │
    └── [AND] Outbound network from runner not controlled
        └── No egress filtering on CI runner network
```

**Primary mitigations by attack path:**

| Attack Path | Primary Control | Secondary Control |
|---|---|---|
| Secrets in logs | Log secret masking; audit for debug flags | Pre-commit secret scanning |
| Secrets in environment | Runtime secret injection (fetch at use, not start) | IMDS hop limit (AWS: `--metadata-token-ttl-seconds 0`) |
| Committed secrets | Pre-commit hooks (Gitleaks); push protection | Git history scanning; immediate rotation on detection |
| Egress exfiltration | Network egress filtering on runners | OIDC short-lived credentials (nothing to steal long-term) |

---

## Real-World CI/CD Breach Examples

### SolarWinds SUNBURST (2020)

**What happened:** Nation-state attackers (attributed to Russia's SVR) compromised SolarWinds' build environment and injected malicious code into the Orion software update process. The malicious code was included in signed, legitimate software updates distributed to approximately 18,000 SolarWinds customers, including the US Treasury, Department of Homeland Security, and numerous Fortune 500 companies.

**CI/CD relevance:** The attackers maintained persistence in the build environment for months, modifying source code during the build process in a way that bypassed code review. This demonstrated that even organizations with rigorous development practices can be compromised if the build environment itself is not adequately protected.

**Key lessons:**
- Build environment integrity must be verified continuously, not assumed
- Build outputs should be reproducible and verifiable independently of the build environment
- Monitoring must extend to the CI/CD infrastructure, not just production systems

### Codecov Breach (2021)

**What happened:** Attackers gained access to Codecov's Docker image creation process and modified the Codecov Bash uploader script to exfiltrate environment variables from any CI environment running the script. The modified script was served from Codecov's official distribution channel for approximately two months before discovery.

**CI/CD relevance:** Thousands of organizations were affected because they consumed a trusted third-party CI/CD tool without verifying its integrity. The tool ran with full access to pipeline environment variables including credentials for cloud providers, source code repositories, and application services.

**Key lessons:**
- Third-party CI/CD tool integrity must be verified via checksums or signature verification
- Pipeline environment variables should be scoped to only the secrets each job needs
- Anomaly detection on network egress from build environments can detect exfiltration

### GitHub Actions Argument Injection (Various, 2022-2023)

**What happened:** Multiple popular open-source projects were found to be vulnerable to argument injection in their GitHub Actions workflows. Attackers could craft pull request titles, branch names, or commit messages containing shell metacharacters that, when interpolated into pipeline scripts, executed attacker-controlled commands.

**CI/CD relevance:** Demonstrates that pipeline configuration code is attack surface requiring the same security scrutiny as application code. Improper input handling in CI/CD configuration files can lead to arbitrary code execution.

**Key lessons:**
- Pipeline configuration files must undergo security review
- External user-controlled inputs (PR titles, branch names, commit messages) must never be directly interpolated into shell commands
- Use action-level input parameters rather than direct shell interpolation

### PyTorch Dependency Confusion Attack (2022)

**What happened:** A security researcher demonstrated a dependency confusion attack against PyTorch's nightly build pipeline by uploading a malicious package to PyPI with the same name as an internal PyTorch dependency. The malicious package was automatically installed in CI builds, demonstrating code execution in the PyTorch build environment.

**Key lessons:**
- Internal package namespacing must prevent confusion with public packages
- CI/CD pipelines should use explicit private registry configuration that prevents fallback to public registries for internal package names
- SCA tooling should flag packages resolved from unexpected registries

---

## Why Secure-by-Default Pipelines Matter

### The Default State is Insecure

Most CI/CD platforms are configured with developer convenience as the primary design goal. Default configurations typically include:
- Broad secret exposure scopes (secrets available to all branches, forks, and pipeline jobs)
- No enforcement of artifact integrity verification
- Mutable action references (tags rather than commit SHAs)
- Verbose logging that may expose sensitive values
- No network egress controls on build environments

Organizations that use default platform configurations without applying security hardening inherit all of these insecure defaults. Secure-by-default pipeline design inverts this posture: security controls are the baseline, and deviations from secure defaults require explicit justification and approval.

### Defense in Depth for Software Delivery

Secure pipeline design provides multiple independent layers of defense:
1. **Pre-commit controls** prevent secrets and vulnerable code from entering the repository
2. **CI security gates** block builds that introduce new vulnerabilities or violate policy
3. **Artifact integrity controls** ensure deployed artifacts are authentic and unmodified
4. **Deployment controls** prevent untested or unapproved changes from reaching production
5. **Runtime monitoring** detects anomalous behavior in production deployments

An adversary attempting to introduce malicious code must successfully bypass all of these layers, significantly raising the cost and complexity of attacks.

### Compliance and Regulatory Foundation

Secure CI/CD pipelines are a foundational requirement for a growing number of regulatory and industry compliance frameworks:
- **Executive Order 14028** (US, 2021) requires federal software suppliers to implement SBOM generation and software supply chain security practices
- **NIST SP 800-218** (SSDF) defines secure software development practices including build environment security
- **SLSA Framework** provides graduated supply chain integrity levels tied to verifiable pipeline security controls
- **PCI-DSS v4.0** requires change management controls and code review processes for payment card processing systems
- **SOC 2** Type II requires evidence of continuous security monitoring and change control

---

## Key Concepts

### CI (Continuous Integration)

A development practice where developers integrate code changes into a shared repository frequently — typically multiple times per day. Each integration is verified by an automated build and test process, enabling early detection of integration conflicts and defects.

### CD (Continuous Delivery / Continuous Deployment)

**Continuous Delivery** ensures software is always in a deployable state. Every code change that passes the CI pipeline can be released to production at any time, but the actual release decision is made by a human.

**Continuous Deployment** automatically deploys every change that passes the pipeline to production without requiring human approval for each release.

### Pipeline as Code

Defining pipeline configuration in version-controlled files (e.g., `.github/workflows/*.yaml`, `.gitlab-ci.yml`, `Jenkinsfile`) enables peer review, audit trails, and consistent security policy for pipeline configuration — treating it with the same rigor as application code.

### Ephemeral Build Environments

Build environments that are created fresh for each pipeline run and destroyed after completion. Ephemeral environments prevent state accumulation between builds, limit the blast radius of a compromised build, and eliminate persistence mechanisms for attackers.

### Artifact Signing and Verification

The process of cryptographically signing build artifacts (container images, binaries, SBOMs) with a private key and verifying the signature before use. Sigstore (Cosign, Fulcio, Rekor) provides open, free tooling for software artifact signing with transparency log guarantees.

### SLSA (Supply-chain Levels for Software Artifacts)

A security framework for grading the supply chain integrity of software artifacts. SLSA defines four levels (SLSA 1–4) with increasing requirements for build environment security, provenance attestation, and artifact integrity verification. Higher SLSA levels provide stronger guarantees that artifacts have not been tampered with.

### Software Bill of Materials (SBOM)

A machine-readable inventory of all software components, libraries, and dependencies included in an application or artifact. SBOMs enable organizations to quickly identify affected software when new vulnerabilities are disclosed. SPDX and CycloneDX are the dominant SBOM formats.

### Pipeline Identity and Access Management (IAM)

The management of identities, credentials, and access permissions for CI/CD pipeline components. Best-practice pipeline IAM uses short-lived, workload-specific credentials issued through OIDC federation rather than long-lived service account keys.

### OIDC Federation for CI/CD

OpenID Connect (OIDC) federation allows CI/CD platforms (GitHub Actions, GitLab CI, etc.) to issue short-lived identity tokens that cloud providers trust for authentication. This eliminates the need to store long-lived cloud credentials (API keys, service account JSON files) as pipeline secrets.

### Break-the-Build

A security gate configuration that causes a CI pipeline to fail and block progression when a security threshold is exceeded — for example, when a SAST scan finds a Critical severity vulnerability, or when an SCA scan identifies a dependency with a CVSS score above 9.0. Break-the-build policies enforce a non-negotiable minimum security standard.

### Provenance

Cryptographically verifiable metadata that records the origin and build history of a software artifact: what source commit was used, what build environment executed the build, what tools were invoked, and what artifact was produced. SLSA provenance attestations are signed by the build system and can be verified at deployment time to confirm an artifact's supply chain integrity. See also: Build provenance (glossary), SLSA.

---

## Lateral Movement in CI/CD Platforms

Lateral movement within CI/CD infrastructure is an underexamined threat category. Once an attacker achieves code execution in one pipeline job, they may be able to pivot to other pipelines, repositories, or cloud environments within the same CI/CD platform.

### Cross-Pipeline Secret Access

CI/CD platforms centralize secrets management as a convenience feature — secrets are stored at the organization or project level and inherited by pipelines. This centralization creates a lateral movement path:

**GitHub Actions — organization-level secrets:**
```
Attack scenario:
1. Attacker achieves code execution in pipeline for repository A (low-security project)
2. Repository A's workflow has access to organization-level secrets (e.g., PROD_DEPLOY_KEY)
   because the organization secret was not restricted to specific repositories
3. Attacker reads PROD_DEPLOY_KEY from the environment and uses it to deploy to production

Defense:
- Restrict organization secrets to specific repositories (not "All repositories")
- Use environment-scoped secrets for production credentials
- Review organization secret access quarterly
```

**Audit: Identify overly-permissive secret access in GitHub:**
```bash
# List organization secrets and their visibility
gh api /orgs/{org}/actions/secrets \
  | jq '.secrets[] | {name: .name, visibility: .visibility, selected_repositories_url: .selected_repositories_url}'

# Alert on any secret with visibility == "all" that contains "PROD" or "DEPLOY" in the name
gh api /orgs/{org}/actions/secrets \
  | jq '[.secrets[] | select(.visibility == "all") | select(.name | test("PROD|DEPLOY|KEY|TOKEN"; "i"))]'
```

### CI/CD Platform Privilege Escalation

**GitHub Actions — GITHUB_TOKEN scope abuse:**
The `GITHUB_TOKEN` automatically granted to every workflow has configurable permissions. Default permissions vary by organization setting. An overly permissive `GITHUB_TOKEN` enables an attacker with code execution to:
- Write to any branch in the repository
- Approve pull requests
- Publish GitHub Releases
- Invoke repository dispatch events (triggering other workflows)

```yaml
# INSECURE — broad default permissions
jobs:
  build:
    runs-on: ubuntu-latest
    # No permissions block — inherits default (potentially write-all)
    steps:
      - run: ./build.sh

# SECURE — minimal permissions, explicitly declared
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read      # Read source code only
      packages: write     # Write to GitHub Packages registry
      id-token: write     # Request OIDC token for cloud auth
      # All other permissions: none (implicitly denied)
    steps:
      - run: ./build.sh
```

**Enforce minimal permissions at the repository level:**
```yaml
# .github/workflows/permissions-policy.yaml
# Org-level setting: default token permissions = "read" for all repos
# This workflow documents the explicit permissions needed
permissions:
  contents: read
  # Additional permissions only as needed and documented
```

**GitLab CI — project token inheritance:**
GitLab's CI_JOB_TOKEN has project-scoped permissions by default, but `CI_JOB_TOKEN allowlist` must be configured to prevent cross-project token use:

```yaml
# GitLab project settings → CI/CD → Token Access
# Restrict which projects can use this project's CI_JOB_TOKEN

# In gitlab-ci.yml, use explicit read-only variables for cross-project references
variables:
  READ_ONLY_TOKEN: $CICD_READ_TOKEN  # Dedicated read-only token, not CI_JOB_TOKEN
```

### Runner Compromise and Persistence

Self-hosted CI/CD runners that are not ephemeral are high-value lateral movement targets. A compromised runner persists between builds, allowing an attacker to:
- Intercept secrets from subsequent pipeline runs
- Modify build outputs before they are published
- Establish persistence on the runner host and use it as a pivot point to internal networks

**Required controls for self-hosted runners:**

```
Ephemeral runners (create-on-demand, destroy-after-use):
├── AWS: CodeBuild, GitHub Actions with Just-in-Time runners
├── GCP: Cloud Build
├── Azure: Azure Container Instances as ephemeral runners
└── Self-hosted: Use runner auto-scaling with ephemeral VMs (GitHub Actions Runners Controller)

Network isolation:
├── Runners must not have access to internal production networks
├── Runners must not have access to other runners' namespaces
└── Runners must only communicate outbound to known CI/CD endpoints

Artifact integrity:
└── Build outputs must be signed before leaving the runner
    (an output from a compromised runner without signing is undetectable)
```

**Detect runner persistence attempts (Falco rule):**
```yaml
# falco_rules.yaml — detect suspicious processes in CI runner containers
- rule: CI Runner Reverse Shell Attempt
  desc: Detect reverse shell or persistence mechanisms in CI runner containers
  condition: >
    spawned_process and
    container and
    container.label.type = "ci-runner" and
    (proc.name in (nc, ncat, socat, bash, sh) and
     proc.args contains "-e" and proc.args contains "/bin/")
  output: >
    Possible reverse shell in CI runner (user=%user.name command=%proc.cmdline
    container=%container.name image=%container.image.repository)
  priority: CRITICAL
```

### Supply Chain Pivot: From Repository to Cloud

The most dangerous lateral movement path is from a compromised repository to cloud infrastructure via the CI/CD pipeline's cloud credentials:

```
Attack chain:
Malicious PR merged (social engineering or dependency confusion)
    → Pipeline triggered with malicious code
    → OIDC token obtained for cloud provider
    → Cloud API called to: exfiltrate secrets, modify IAM, deploy backdoored infrastructure
    → Persistence established in cloud environment

Defense chain (every step must hold):
1. OIDC token scope: token scoped to minimum permissions (read-only for most workflows)
2. Environment protection: production OIDC only available to protected-branch workflows
3. Admission control: IaC changes require approval; policy-as-code blocks privilege escalation
4. CloudTrail/audit: all API calls logged; anomalous calls alert within minutes
5. Immutable audit: CloudTrail logs written to S3 with Object Lock; cannot be deleted by the pipeline's IAM role
```

A verifiable record of how a software artifact was produced — including the source repository, commit hash, build system, build inputs, and build configuration. Provenance attestations (as defined by SLSA) allow consumers of artifacts to verify their supply chain integrity.
