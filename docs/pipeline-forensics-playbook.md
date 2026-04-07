# CI/CD Pipeline Compromise — Forensics and Investigation Playbook

This playbook provides structured investigation procedures for suspected CI/CD pipeline compromises. It covers evidence preservation, root cause analysis, blast radius assessment, and the specific commands used to extract relevant artifacts from common CI/CD platforms. It is designed to be used alongside the [Threat Model](threat-model.md) and [Architecture](architecture.md) documents.

**Prerequisites for effective investigation:**
- Pipeline audit logs enabled and shipped to a tamper-evident store (CloudTrail, SIEM)
- SLSA provenance attestations generated for all build artifacts
- Secret audit logging enabled (Vault audit, AWS Secrets Manager CloudTrail, Azure Key Vault diagnostics)
- Artifact signing with Cosign and signature verification in promotion gates

If these pre-requisites are not met, investigation capability will be severely limited.

---

## Table of Contents

1. [Incident Recognition and Severity Classification](#incident-recognition-and-severity-classification)
2. [Initial Triage](#initial-triage)
3. [Evidence Preservation Protocol](#evidence-preservation-protocol)
4. [Investigation Playbooks by Compromise Type](#investigation-playbooks-by-compromise-type)
   - [PL-01: Malicious Code Injected into Pipeline Definition](#pl-01-malicious-code-injected-into-pipeline-definition)
   - [PL-02: Compromised Build Artifact](#pl-02-compromised-build-artifact)
   - [PL-03: Secret Exfiltration from Pipeline](#pl-03-secret-exfiltration-from-pipeline)
   - [PL-04: Unauthorized Pipeline Trigger or Execution](#pl-04-unauthorized-pipeline-trigger-or-execution)
   - [PL-05: Supply Chain Dependency Compromise](#pl-05-supply-chain-dependency-compromise)
   - [PL-06: Build Runner Compromise](#pl-06-build-runner-compromise)
5. [Blast Radius Assessment Framework](#blast-radius-assessment-framework)
6. [Artifact Integrity Verification Procedures](#artifact-integrity-verification-procedures)
7. [Pipeline Hardening After Compromise](#pipeline-hardening-after-compromise)
8. [Investigation Evidence Checklist](#investigation-evidence-checklist)

---

## Incident Recognition and Severity Classification

### Detection Signals That Indicate Pipeline Compromise

| Signal | Source | Probable Compromise Type |
|--------|--------|-------------------------|
| Unexpected outbound network connection from CI runner | Network monitoring, runner egress logs | Secret exfiltration, C2 beacon |
| Pipeline definition file modified without change request | Branch protection bypass, CODEOWNERS violation | Malicious pipeline modification |
| Artifact signature verification failure at promotion gate | Registry, Cosign verify output | Artifact tampering |
| Secret accessed from an IP address outside runner CIDR | Vault audit log, Secrets Manager CloudTrail | Credential theft from pipeline |
| SLSA provenance attestation missing or invalid | in-toto/SLSA verification | Unsigned artifact of unknown origin deployed |
| New external account added to CI/CD platform | Platform audit log | Attacker persistence via OAuth app or SCM integration |
| Pipeline run triggered outside of normal commit/PR events | CI audit log | Unauthorized pipeline execution |
| Excessive secret read volume from a CI service account | Secrets Manager CloudTrail, Vault audit | Credential harvesting |
| Base image digest changed in registry without rebuild pipeline run | Image registry audit | Supply chain injection |

### Severity Classification

| Severity | Criteria | Initial Response Time |
|----------|----------|----------------------|
| **P1 — Critical** | Compromised artifact deployed to production; secrets confirmed exfiltrated; pipeline used to access production systems | Immediate (5 min) |
| **P2 — High** | Compromise confirmed but contained to CI environment; secrets potentially exfiltrated but not confirmed; artifact tampering detected before production | < 30 minutes |
| **P3 — Medium** | Suspicious signals; unconfirmed compromise; investigation required to rule out false positive | < 4 hours |

---

## Initial Triage

Execute these steps immediately upon receiving a pipeline compromise alert:

```
[ ] Determine: Is this an active compromise or a historical finding?
    - Active: Is the pipeline currently running with potentially malicious steps?
    - Historical: When did the compromise occur? What artifacts were produced?

[ ] Determine: Was any artifact produced during the compromise window deployed?
    - To staging only? (Lower severity)
    - To production? (Critical severity — activate full IR team)

[ ] Determine: What secrets were available to the compromised pipeline?
    - Which secret stores did the pipeline have access to?
    - Which cloud credentials, API keys, or signing keys were injected?

[ ] Stop new pipeline runs on the affected repository until scope is determined:
    # GitHub Actions — disable workflow
    gh workflow disable <workflow-name> --repo <org/repo>

    # GitLab CI — pause the pipeline
    # Via GitLab API:
    curl --request POST \
      --header "PRIVATE-TOKEN: <PAT>" \
      "https://gitlab.example.com/api/v4/projects/<PROJECT_ID>/pipelines/<PIPELINE_ID>/cancel"

[ ] Preserve: Do not modify any repository state, pipeline configuration, or
    log files until evidence has been captured.
```

---

## Evidence Preservation Protocol

Preserving evidence before remediation is critical. Many remediation actions (closing PRs, deleting branches, rotating secrets) destroy evidence.

### What to Preserve

| Evidence Type | Collection Method | Retention |
|---------------|------------------|-----------|
| Pipeline run logs (all steps) | Export from CI platform | 90 days |
| Pipeline definition at time of compromise (git commit SHA) | `git show <SHA>:path/to/workflow.yml` | Permanent |
| Build artifact digest | Registry manifest digest | 90 days |
| SLSA provenance attestation | `cosign verify-attestation` output | 90 days |
| Secret access logs | Vault audit export, Secrets Manager CloudTrail | 90 days |
| Network egress logs from runner | Cloud VPC Flow Logs, runner platform audit | 90 days |
| CI platform audit log | Platform-specific export (see below) | 90 days |
| Git history including any force-push or history rewrite events | `git reflog` from repository | Permanent |

### Evidence Collection Commands

**GitHub Actions:**
```bash
# Export workflow run details
gh run view <RUN_ID> --repo <org/repo> --json \
  startedAt,updatedAt,event,headCommit,triggeredBy,status,jobs \
  > workflow-run-evidence.json

# Export workflow run logs
gh run view <RUN_ID> --repo <org/repo> --log > workflow-run-logs.txt

# Export the workflow definition at the time of the run
git show <HEAD_SHA>:.github/workflows/<workflow-file>.yml > workflow-at-incident.yml

# Export GitHub audit log (requires GitHub Enterprise or Organization admin)
gh api /orgs/<ORG>/audit-log \
  --paginate \
  --field phrase="action:workflows" \
  > github-audit-log.json
```

**GitLab CI:**
```bash
# Export pipeline details via API
curl --header "PRIVATE-TOKEN: <PAT>" \
  "https://gitlab.example.com/api/v4/projects/<PROJECT_ID>/pipelines/<PIPELINE_ID>" \
  > pipeline-evidence.json

# Export job logs
curl --header "PRIVATE-TOKEN: <PAT>" \
  "https://gitlab.example.com/api/v4/projects/<PROJECT_ID>/jobs/<JOB_ID>/trace" \
  > job-log.txt

# Export audit events
curl --header "PRIVATE-TOKEN: <PAT>" \
  "https://gitlab.example.com/api/v4/audit_events?created_after=<ISO8601>&per_page=100" \
  > gitlab-audit.json
```

**Jenkins:**
```bash
# Export build console output
curl -u <USER>:<API_TOKEN> \
  "http://jenkins.example.com/job/<JOB_NAME>/<BUILD_NUMBER>/consoleText" \
  > jenkins-build-log.txt

# Export build details
curl -u <USER>:<API_TOKEN> \
  "http://jenkins.example.com/job/<JOB_NAME>/<BUILD_NUMBER>/api/json?pretty=true" \
  > jenkins-build-details.json
```

**HashiCorp Vault:**
```bash
# Export audit log entries for the pipeline secret path
grep "\"path\":\"secret/data/<SERVICE>\"" /var/log/vault/audit.log \
  | jq 'select(.time > "<INCIDENT_START>")' \
  > vault-secret-access.json
```

**AWS Secrets Manager:**
```bash
# Export CloudTrail events for secret access
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceName,AttributeValue=<SECRET_ARN> \
  --start-time <INCIDENT_WINDOW_START> \
  --end-time <INCIDENT_WINDOW_END> \
  --output json > secrets-manager-access.json
```

---

## Investigation Playbooks by Compromise Type

### PL-01: Malicious Code Injected into Pipeline Definition

**Indicators:**
- Unexpected pipeline steps in workflow files
- Unusual `curl`, `wget`, `ssh`, or `nc` commands in pipeline scripts
- New `env:` variables injected in steps that reference known secret names
- Base64-encoded commands in pipeline steps

**Investigation Steps:**

```bash
# 1. Identify when the pipeline definition was last modified
git log --oneline -- .github/workflows/<workflow.yml>
git log --oneline -- .gitlab-ci.yml
git log --oneline -- Jenkinsfile

# 2. Diff the current pipeline definition against the last known-good state
git diff <LAST_KNOWN_GOOD_SHA>..<INCIDENT_SHA> -- .github/workflows/<workflow.yml>

# 3. Check for any temporary branches that ran the compromised pipeline
git branch -a | grep -v HEAD | xargs -I {} git log --oneline -3 {}

# 4. Review who approved the PR or commit that introduced the change
gh pr list --repo <org/repo> --state merged \
  --json number,title,mergedAt,mergedBy,headRefName \
  --limit 50 > merged-prs.json

# 5. Check for CODEOWNERS bypass — was review from a code owner obtained?
gh api /repos/<org/repo>/commits/<INCIDENT_SHA>/status

# 6. Search for encoded or obfuscated commands in pipeline files
grep -rn "base64\|eval\|exec\|/dev/tcp\|/dev/udp" .github/workflows/
grep -rn "curl.*sh\|wget.*sh\|bash.*<(curl" .github/workflows/

# 7. Check for use of third-party GitHub Actions at non-pinned SHAs
grep -rn "uses:.*@" .github/workflows/ | grep -v "@[a-f0-9]\{40\}"
# Result: lines not pinned to a full SHA commit — investigate each
```

**Root Cause Identification:**
- Verify if the commit author's account had MFA enabled.
- Check GitHub/GitLab audit log for account compromise signals (login from new location, API key issuance).
- Review whether branch protection rules were bypassed (admin bypass, rule exception).

---

### PL-02: Compromised Build Artifact

**Indicators:**
- Artifact signature verification fails in a promotion gate
- Artifact digest in registry does not match the SLSA provenance record
- Artifact produced at a time when no pipeline run was executing
- Artifact pushed by an identity that is not the authorized CI service account

**Investigation Steps:**

```bash
# 1. Verify the artifact signature
cosign verify \
  --certificate-identity-regexp "^https://github.com/<org>/<repo>/" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  <REGISTRY>/<IMAGE>@<DIGEST>

# 2. If signature is present but verification fails, extract the certificate for analysis
cosign verify \
  --certificate-identity-regexp ".*" \
  --certificate-oidc-issuer ".*" \
  <REGISTRY>/<IMAGE>@<DIGEST> 2>&1 | jq '.[0].optional'

# 3. Verify the SLSA provenance attestation
cosign verify-attestation \
  --type slsaprovenance \
  --certificate-identity-regexp "^https://github.com/<org>/<repo>/" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  <REGISTRY>/<IMAGE>@<DIGEST> \
  | jq '.payload | @base64d | fromjson | .predicate'

# 4. Determine what pipeline run produced the artifact
# The SLSA provenance will contain:
# - buildInvocationId (links to the CI run)
# - materials (source code digest)
# - builder.id (the pipeline platform and workflow)

# 5. Verify the source code digest in the provenance matches the expected commit
# Extract from provenance:
EXPECTED_COMMIT=$(cosign verify-attestation ... | jq -r '.predicate.buildConfig.steps[0].environment.GITHUB_SHA')
# Compare against the commit you expect

# 6. Check registry push audit log for who pushed the artifact
# AWS ECR:
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=PutImage \
  --start-time <INCIDENT_WINDOW> \
  --output json | jq '.Events[] | {time: .EventTime, user: .Username, resource: .Resources}'

# Docker Hub or GHCR: Review registry access audit logs via platform UI
```

**If artifact is confirmed tampered:**
1. Immediately pull it from all environments (flag as `Do Not Use` in registry, apply deny policy in admission controller).
2. Identify all environments where the artifact was deployed and execute the relevant cloud incident response playbook.
3. Treat any secrets available to that artifact's runtime environment as compromised.

---

### PL-03: Secret Exfiltration from Pipeline

**Indicators:**
- Unexpected outbound HTTP/HTTPS POST from CI runner during a build
- Secret accessed from an IP not belonging to the CI runner network range
- `curl` or `wget` call with a payload in pipeline logs
- Secret rotation triggered by anomaly detection

**Investigation Steps:**

```bash
# 1. Identify all secrets the pipeline had access to during the suspect run
# Review the workflow file for all secret references:
grep -n "secrets\.\|SECRETS_\|AWS_SECRET\|TOKEN\|API_KEY\|PRIVATE_KEY" \
  .github/workflows/<workflow.yml>

# 2. Review Vault/Secrets Manager access logs for the pipeline service account
# Vault:
grep '"service_account":"<PIPELINE_SA>"' /var/log/vault/audit.log \
  | jq '. | select(.time >= "<INCIDENT_START>")'

# AWS Secrets Manager:
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=<PIPELINE_ROLE_NAME> \
  --start-time <INCIDENT_WINDOW>

# 3. Check runner network egress for unexpected destinations
# If runners are on AWS, check VPC Flow Logs:
aws logs filter-log-events \
  --log-group-name /vpc-flow-logs/<VPC_ID> \
  --start-time <EPOCH_MS_INCIDENT_START> \
  --filter-pattern "[version, account, eni, source, destination, srcport, destport, protocol, packets, bytes, start, end, action=ACCEPT, status]" \
  | jq '.events[].message' | awk '{print $5, $6, $7, $8}' | sort | uniq -c | sort -rn

# 4. Search pipeline logs for data exfiltration patterns
grep -E "curl.*-d|wget.*--post-data|nc.*[0-9]+\.[0-9]+|/dev/tcp" workflow-run-logs.txt

# 5. For each secret confirmed as potentially exfiltrated, trigger rotation:
# - Cloud credentials: disable and reissue
# - API keys: revoke at the issuing service
# - Signing keys (Cosign): revoke the signing certificate, reissue, resign all artifacts
# - Database passwords: rotate at the database level, update secret store, restart services
```

**Post-Exfiltration Actions:**
1. Rotate ALL secrets the pipeline had access to, even those you cannot confirm were exfiltrated.
2. Review all downstream services that use those secrets — they must be considered compromised until rotated.
3. Enable secret scanning on all repositories.
4. Implement egress filtering on all CI runners.

---

### PL-04: Unauthorized Pipeline Trigger or Execution

**Indicators:**
- Pipeline run triggered by an unknown identity or GitHub App
- Pipeline run event type is `workflow_dispatch` or `repository_dispatch` not matching normal usage
- Pipeline run executed on a branch that should not trigger builds (e.g., an attacker-controlled fork's branch targeting privileged workflows)

**Investigation Steps:**

```bash
# 1. Identify the trigger identity and event
gh run view <RUN_ID> --repo <org/repo> --json \
  event,triggeredBy,headCommit,headBranch,headSha

# 2. For GitHub Actions: check if the run was triggered from a fork
# PR from fork runs should not have access to secrets by default
# Check GITHUB_REPOSITORY_OWNER and GITHUB_ACTOR in the run context

# 3. Check for GitHub Actions environment approvals that were bypassed
gh api /repos/<org/repo>/environments/<env>/deployment-protection-rules

# 4. Review GitHub audit log for unauthorized workflow_dispatch events
gh api /orgs/<ORG>/audit-log \
  --field phrase="action:workflows.dispatched_workflow_run" \
  --paginate

# 5. Check for malicious GitHub Apps or OAuth apps authorized to the repository
gh api /repos/<org/repo>/installations

# 6. Verify webhook configurations for unauthorized additions
gh api /repos/<org/repo>/hooks
```

---

### PL-05: Supply Chain Dependency Compromise

**Indicators:**
- SCA tool alerts on a newly malicious package version
- Known malicious package published to npm/PyPI/Maven/RubyGems (e.g., typosquatting, account takeover)
- Unexpected behavior from a dependency package (network calls, file system writes outside expected paths)

**Investigation Steps:**

```bash
# 1. Identify which builds used the compromised package version
# Search package lock files committed to the repository:
git log --all --follow -p package-lock.json | grep "<PACKAGE_NAME>"

# 2. Identify the exact versions consumed in affected builds
# For npm:
cat package-lock.json | jq '.packages["node_modules/<PACKAGE_NAME>"].version'

# For Python:
cat requirements.txt | grep <PACKAGE_NAME>
pip show <PACKAGE_NAME> | grep Version

# 3. Determine which artifacts were built with the compromised dependency
# Check the SBOM for each artifact:
cosign verify-attestation \
  --type cyclonedx \
  <REGISTRY>/<IMAGE>@<DIGEST> \
  | jq '.payload | @base64d | fromjson | .components[] | select(.name == "<PACKAGE_NAME>")'

# 4. Assess the capability of the compromised package:
# - Did it have network access? (Check egress logs from runners during affected builds)
# - Did it write to the filesystem?
# - Did it modify environment variables?
# - Did it access other packages' data?

# 5. Determine whether the malicious code executed at install time, build time, or runtime
# (install-time scripts in package.json or setup.py are highest risk)
```

**Response:**
1. Pin all dependencies to exact verified digests (not version strings).
2. Update to a clean version of the affected package.
3. Rebuild all artifacts produced during the affected window.
4. Re-deploy rebuilt artifacts to all environments.
5. If the malicious package had network or filesystem access at build time, treat build secrets as compromised.

---

### PL-06: Build Runner Compromise

**Indicators:**
- Evidence of persistence mechanisms on a self-hosted runner (cron jobs, systemd services added)
- Runner is making network connections not associated with any current build
- Runner files modified outside of build execution windows
- Multiple builds sharing one runner with evidence of data leakage between jobs

**Investigation Steps:**

```bash
# 1. Isolate the runner immediately — remove it from the runner pool
# GitHub Actions:
# Deregister via UI: Settings > Actions > Runners > <Runner> > Remove

# 2. Do NOT wipe the runner yet — take a filesystem snapshot first
# If the runner is an EC2 instance:
aws ec2 create-snapshot \
  --volume-id <ROOT_VOLUME_ID> \
  --description "Runner forensic snapshot $(date +%Y%m%d-%H%M)"

# 3. Examine runner process list for suspicious activity
ps aux > /tmp/runner-processes.txt

# 4. Check for unauthorized cron jobs or systemd services
crontab -l > /tmp/crontab.txt
systemctl list-units --type=service --state=active > /tmp/systemd-services.txt
ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ > /tmp/cron-dirs.txt

# 5. Review recently modified files on the runner
find / -newer /tmp/reference-timestamp -type f \
  ! -path "/proc/*" ! -path "/sys/*" \
  -ls > /tmp/recently-modified.txt 2>/dev/null

# 6. Examine outbound network connections
netstat -anp > /tmp/network-connections.txt
ss -anp > /tmp/socket-state.txt

# 7. Check runner logs for anomalous job execution
journalctl -u actions.runner.* --since "<INCIDENT_START>" > /tmp/runner-journal.txt

# 8. For self-hosted runners, examine the _work directory for data from other jobs
ls -la <RUNNER_DIR>/_work/

# 9. Determine what builds ran on this runner and treat all their outputs as suspect
# GitHub: filter workflow runs by runner name in audit logs
gh api /orgs/<ORG>/audit-log \
  --field phrase="action:workflows.run" \
  --paginate > runner-runs.json
```

**Eradication:**
1. Terminate the compromised runner instance.
2. Launch a fresh runner from a known-good base AMI/image.
3. All artifacts produced on the compromised runner must be considered untrusted — rebuild them.
4. Treat all secrets that were injected into builds on that runner as compromised and rotate them.
5. For shared runners: assess cross-job data leakage — all jobs that ran on the runner during the compromise window may have been affected.

---

## Blast Radius Assessment Framework

After any confirmed pipeline compromise, use this framework to systematically assess the full scope of impact:

```
Step 1: Timeline establishment
─────────────────────────────
Determine the earliest possible compromise time (not just when detected)
and the latest time the compromised system was isolated.

Compromise window: [T_start] → [T_containment]

Step 2: Artifact enumeration
────────────────────────────
List all artifacts produced during the compromise window:
[ ] Container images (with digests)
[ ] Binary packages (with checksums)
[ ] Infrastructure artifacts (Terraform plans, Helm charts)
[ ] SBOMs generated during this window

Step 3: Deployment mapping
──────────────────────────
For each artifact produced during the window:
[ ] Was it deployed? To which environments?
[ ] When was it deployed?
[ ] Is it still running in production?

Step 4: Secret exposure mapping
────────────────────────────────
List all secrets injected into pipeline runs during the window:
[ ] Cloud credentials (IAM roles, service principals)
[ ] API keys and tokens
[ ] Signing keys (Cosign, GPG)
[ ] Database credentials
[ ] Third-party service API keys

For each secret: confirm whether rotation is required.

Step 5: Downstream impact
──────────────────────────
[ ] Which services depend on the potentially compromised artifacts?
[ ] Which services authenticate with the potentially compromised secrets?
[ ] Were any downstream environments (staging, prod) affected?
[ ] Were any customers exposed to a potentially compromised service?

Step 6: Notification obligations
────────────────────────────────
[ ] Internal: engineering teams, CISO, CTO, legal
[ ] Customer notification: required if customer data may have been exposed
[ ] Regulatory: required if regulated data was potentially compromised
[ ] Vendor notification: required if third-party supply chain involvement confirmed
```

---

## Artifact Integrity Verification Procedures

During an investigation, you may need to rapidly verify the integrity of artifacts across environments. These procedures can be run against any container image or artifact.

```bash
# Verify a container image is signed and the provenance matches expected origin
REGISTRY="<your-registry>"
IMAGE="<image-name>"
DIGEST="<sha256:digest>"
EXPECTED_REPO="https://github.com/<org>/<repo>"
OIDC_ISSUER="https://token.actions.githubusercontent.com"

# Step 1: Verify signature
echo "=== Verifying signature ==="
cosign verify \
  --certificate-identity-regexp "^${EXPECTED_REPO}/" \
  --certificate-oidc-issuer "${OIDC_ISSUER}" \
  "${REGISTRY}/${IMAGE}@${DIGEST}" \
  && echo "PASS: Signature valid" \
  || echo "FAIL: Signature invalid or missing"

# Step 2: Verify SLSA provenance
echo "=== Verifying SLSA provenance ==="
cosign verify-attestation \
  --type slsaprovenance \
  --certificate-identity-regexp "^${EXPECTED_REPO}/" \
  --certificate-oidc-issuer "${OIDC_ISSUER}" \
  "${REGISTRY}/${IMAGE}@${DIGEST}" \
  | jq '.payload | @base64d | fromjson | {
      builder: .predicate.builder.id,
      source: .predicate.invocation.configSource.uri,
      commit: .predicate.invocation.configSource.digest.sha1,
      buildTime: .predicate.metadata.buildStartedOn
    }'

# Step 3: Verify SBOM attestation if present
echo "=== Verifying SBOM attestation ==="
cosign verify-attestation \
  --type cyclonedx \
  --certificate-identity-regexp "^${EXPECTED_REPO}/" \
  --certificate-oidc-issuer "${OIDC_ISSUER}" \
  "${REGISTRY}/${IMAGE}@${DIGEST}" \
  | jq '.payload | @base64d | fromjson | .components | length'
# Output: number of components in the SBOM; compare against expected baseline

# Step 4: Scan the image for known vulnerabilities
echo "=== Scanning for vulnerabilities ==="
trivy image --exit-code 1 --severity CRITICAL,HIGH \
  "${REGISTRY}/${IMAGE}@${DIGEST}"
```

---

## Pipeline Hardening After Compromise

After completing an investigation, apply these hardening measures before resuming pipeline operations:

### Immediate (before next pipeline run)

- [ ] Rotate all secrets the pipeline had access to
- [ ] Pin all GitHub Actions to full commit SHAs
- [ ] Enable required code review for all pipeline definition files (CODEOWNERS)
- [ ] Enforce `pull_request_target` isolation for fork contributions
- [ ] Restrict `workflow_dispatch` to authorized users only

### Short-term (within 72 hours)

- [ ] Implement egress filtering on all self-hosted runners
- [ ] Enable secret scanning across all repositories
- [ ] Add SLSA provenance generation to all build pipelines
- [ ] Implement admission control to verify artifact signatures at deployment
- [ ] Enable Dependabot or Renovate with auto-merge for security patches

### Structural (within 30 days)

- [ ] Migrate to ephemeral runners (eliminate self-hosted persistent runner risk)
- [ ] Implement private dependency mirror to reduce supply chain exposure
- [ ] Deploy Sigstore policy controller or Kyverno to enforce image signature verification
- [ ] Enable OIDC federation for all cloud provider authentication (eliminate long-lived credentials)
- [ ] Configure CI service accounts with minimum required permissions (no wildcard policies)

---

## Investigation Evidence Checklist

Use this checklist to confirm all evidence has been captured before making any remediation changes:

```
Pipeline Evidence
─────────────────
[ ] Pipeline run logs exported (all steps, all jobs)
[ ] Pipeline definition file at incident commit SHA captured
[ ] Git log for pipeline definition files exported
[ ] PR/merge request details that introduced changes captured
[ ] CI platform audit log exported for incident window

Artifact Evidence
─────────────────
[ ] Digest of all artifacts produced during window recorded
[ ] Cosign signature verification output captured
[ ] SLSA provenance attestation extracted and saved
[ ] SBOM for affected artifacts captured
[ ] Registry push audit log exported

Secret Access Evidence
──────────────────────
[ ] Vault audit log for pipeline service account exported
[ ] Secrets Manager / Key Vault access logs exported
[ ] CI platform secret access log exported (if available)
[ ] Network egress logs from CI runners captured

Identity Evidence
─────────────────
[ ] Source control platform audit log exported
[ ] OAuth app and GitHub App authorizations recorded
[ ] Runner registration and deregistration events captured

Deployment Evidence
────────────────────
[ ] List of environments where affected artifacts were deployed
[ ] Deployment timestamps for all affected artifacts
[ ] Runtime environment configurations at time of deployment
```

---

*This playbook complements the controls defined in [threat-model.md](threat-model.md) and [framework.md](framework.md). The threat model provides the theoretical basis for each attack type; this playbook provides the operational response.*

*See also:*
- *[architecture.md](architecture.md) — logging and audit trail pre-requisites*
- *[software-supply-chain-security-framework: incident-response-playbook.md](../../software-supply-chain-security-framework/docs/incident-response-playbook.md) — supply chain specific procedures*
- *[cloud-security-devsecops: incident-response-playbooks.md](../../cloud-security-devsecops/docs/incident-response-playbooks.md) — cloud credential compromise procedures*
