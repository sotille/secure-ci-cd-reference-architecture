# Container Registry Security Hardening Guide

The container registry is the distribution hub between CI/CD pipeline and deployment. It is a high-value target: compromising a registry allows an attacker to inject malicious images that will be deployed across every environment that pulls from it. This guide defines the security controls required to harden container registries and the access patterns that connect them to secure pipelines.

---

## Threat Model

Understanding what attackers target in container registries informs the control set required.

| Threat | Attack Vector | Impact | Control |
|--------|-------------|--------|---------|
| **Malicious image injection** | Compromised CI credentials push a trojanized image | Malware deployed to every environment pulling the image | Image signing + signature verification at pull |
| **Dependency confusion / typosquatting** | Attacker publishes a package with the same name as an internal package on a public registry | Pipeline pulls attacker-controlled image instead of trusted internal image | Explicit registry mirrors; deny-list public image pulls |
| **Tag mutability attack** | Attacker overwrites a mutable tag (e.g., `:latest`) with a different image | Previously verified image replaced silently | Immutable tags in production; pull by digest, not tag |
| **Registry credential theft** | Long-lived registry credentials leaked via secrets exposure or insider threat | Full read/write access to all registry content | Workload identity (OIDC); short-lived tokens; no long-lived keys |
| **Stale vulnerable image proliferation** | Old images with known CVEs remain in registry and are pulled by misconfigured deployments | Known vulnerabilities deployed despite patching in newer versions | Registry lifecycle policies; continuous background image scanning |
| **Sensitive data in layers** | Developer accidentally includes secrets, private keys, or PII in an image layer | Credential or data exposure from anyone with pull access | Image scanning for embedded secrets; multi-stage builds |
| **Unauthorized access to private images** | Overly permissive registry ACLs; token sharing across projects | IP theft; exposure of proprietary code or configuration | Namespace-scoped access controls; per-project tokens |

---

## Registry Access Control Architecture

### Principle: Minimal-Scope Credentials

Every entity that interacts with the registry — pipelines, deployment agents, developer workstations — must have the minimum permission required for its function.

| Actor | Required Permission | Anti-pattern |
|-------|--------------------|-----------  |
| **CI build pipeline** | Push to specific namespace only; no delete | Admin-level token shared across all pipelines |
| **Deployment system (staging)** | Pull from staging namespace only | Same credentials used for push and pull |
| **Deployment system (production)** | Pull from production-promoted namespace only | Pipeline credentials reused in production deployment |
| **Security scanner** | Pull from all namespaces; no push or delete | Scanner has write access |
| **Developer workstation** | Pull from development namespace; no push to production | Developer has production push rights |

### Workload Identity for Pipelines

Avoid storing long-lived registry credentials in CI/CD secrets. Use workload identity federation to obtain short-lived tokens at runtime:

**GitHub Actions → AWS ECR (no stored credentials):**

```yaml
- name: Configure AWS credentials via OIDC
  uses: aws-actions/configure-aws-credentials@v4
  with:
    role-to-assume: arn:aws:iam::ACCOUNT_ID:role/ecr-push-role
    aws-region: us-east-1

- name: Authenticate to Amazon ECR
  id: login-ecr
  uses: aws-actions/amazon-ecr-login@v2
  # Generates a short-lived token valid for 12 hours — no static credentials
```

**Azure Pipelines → Azure Container Registry (managed identity):**

```yaml
# Use the Docker@2 task with a service connection backed by a managed identity
# No credentials stored in pipeline variables
- task: Docker@2
  inputs:
    command: 'login'
    containerRegistry: 'acr-service-connection'
    # The service connection is backed by a workload identity federation
    # or managed identity — no client secret required
```

**GitLab CI → Harbor (short-lived robot account token):**

```yaml
build:
  script:
    # Use CI_JOB_JWT_V2 with Harbor's OIDC provider integration
    # Harbor issues a scoped robot token for the duration of the job
    - |
      TOKEN=$(curl -s -X POST "https://harbor.internal/service/token" \
        -H "Content-Type: application/json" \
        -d "{\"provider\":\"gitlab\",\"id_token\":\"${CI_JOB_JWT_V2}\"}" \
        | jq -r '.token')
      docker login harbor.internal --username robot$ci --password "${TOKEN}"
```

---

## Image Promotion Architecture

A fundamental registry security control is the **promotion model**: images are not pushed directly to the production registry. They move through a staged promotion workflow where each stage adds a verification layer.

```
CI Pipeline
    │
    ▼
[dev registry]               ← CI pushes unverified build artifacts
    │
    │  [SAST + SCA + secrets scan pass]
    │  [Image vulnerability scan pass]
    │  [Image signed with pipeline identity]
    ▼
[staging registry]           ← Promotion gate: only verified, signed images
    │
    │  [DAST pass against staging deployment]
    │  [Compliance validation pass]
    │  [Manual approval (change management)]
    ▼
[production registry]        ← Promotion gate: only staging-validated images
    │
    ▼
[Kubernetes admission controller verifies signature before running pod]
```

**Implementation with OCI registries (skopeo copy):**

```bash
# Promote image from dev to staging registry
# Verification of signature required before copy

# 1. Verify the image signature (cosign)
cosign verify \
  --certificate-identity="https://github.com/your-org/your-repo/.github/workflows/build.yml@refs/heads/main" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
  dev-registry.internal/app:${BUILD_ID}

# 2. Copy by digest (immutable — tag cannot be overwritten after this)
DIGEST=$(docker inspect --format='{{index .RepoDigests 0}}' dev-registry.internal/app:${BUILD_ID})
skopeo copy \
  --src-no-creds \
  --dest-creds="${STAGING_REGISTRY_USER}:${STAGING_REGISTRY_TOKEN}" \
  "docker://${DIGEST}" \
  "docker://staging-registry.internal/app:${BUILD_ID}"
```

---

## Immutable Tags and Pull-by-Digest

Mutable image tags are a security liability. The `:latest` tag and version tags like `:1.2.3` can be overwritten after deployment manifests reference them, causing deployed workloads to silently run different code than what was verified.

**Enforcement rules:**

1. **Never use `:latest` in deployment manifests.** Use the immutable build ID tag or, better, the image digest.
2. **Pull by digest in production.** A digest (`sha256:abc123...`) is cryptographically bound to specific image content and cannot be overwritten.
3. **Enable tag immutability in your registry** (supported by ECR, ACR, Harbor, and Artifactory):

```bash
# AWS ECR — enable image tag immutability
aws ecr put-image-tag-mutability \
  --repository-name your-app \
  --image-tag-mutability IMMUTABLE

# Attempt to push a duplicate tag will now fail with ImageAlreadyExistsException
```

```hcl
# Terraform — ECR with tag immutability
resource "aws_ecr_repository" "app" {
  name                 = "your-app"
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.ecr.arn
  }
}
```

**Kubernetes deployment — pull by digest:**

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: your-app
spec:
  template:
    spec:
      containers:
        - name: app
          # Pull by digest — immune to tag reassignment attacks
          image: registry.internal/your-app@sha256:a1b2c3d4e5f6...
          imagePullPolicy: IfNotPresent
```

---

## Registry Lifecycle Policies

Stale images accumulate vulnerable dependencies. Define lifecycle policies that automatically clean up images that are no longer in active use while preserving audit evidence.

**Retention strategy:**

| Image Category | Retention Policy | Rationale |
|---------------|-----------------|-----------|
| Production-promoted images | Retain for 365 days minimum | Rollback capability; audit evidence |
| Staging images | Retain for 90 days | Incident investigation; regression testing |
| Development/PR images | Retain for 7 days | Reduce storage cost; no audit value |
| Untagged images | Delete after 1 day | Dangling layers from failed builds |

**AWS ECR lifecycle policy:**

```json
{
  "rules": [
    {
      "rulePriority": 1,
      "description": "Expire untagged images after 1 day",
      "selection": {
        "tagStatus": "untagged",
        "countType": "sinceImagePushed",
        "countUnit": "days",
        "countNumber": 1
      },
      "action": { "type": "expire" }
    },
    {
      "rulePriority": 2,
      "description": "Keep last 10 production-tagged images",
      "selection": {
        "tagStatus": "tagged",
        "tagPrefixList": ["prod-"],
        "countType": "imageCountMoreThan",
        "countNumber": 10
      },
      "action": { "type": "expire" }
    },
    {
      "rulePriority": 3,
      "description": "Expire dev images after 7 days",
      "selection": {
        "tagStatus": "tagged",
        "tagPrefixList": ["dev-", "pr-"],
        "countType": "sinceImagePushed",
        "countUnit": "days",
        "countNumber": 7
      },
      "action": { "type": "expire" }
    }
  ]
}
```

---

## Continuous Background Image Scanning

Image scanning at build time is necessary but not sufficient. Vulnerabilities are discovered continuously after an image is built. Registry-integrated scanning monitors images already in production for newly disclosed CVEs.

**Scanning architecture:**

```
Build-time scan (Trivy/Grype in CI)
  ↓
Push to registry
  ↓
Registry native scan on push (ECR Enhanced Scanning / ACR Defender / Harbor Trivy)
  ↓
Continuous background rescan (scheduled)
  ↓
Alert on new CRITICAL/HIGH findings → PagerDuty / Jira ticket
  ↓
SLA enforcement (7 days for CRITICAL, 30 days for HIGH)
```

**AWS ECR Enhanced Scanning (Inspector integration):**

```hcl
# Enable ECR Enhanced Scanning org-wide
resource "aws_inspector2_enabler" "ecr" {
  account_ids    = [data.aws_caller_identity.current.account_id]
  resource_types = ["ECR"]
}

# CloudWatch alert for critical ECR findings
resource "aws_cloudwatch_event_rule" "ecr_critical_finding" {
  name        = "ecr-critical-vulnerability"
  description = "Alert on critical vulnerabilities in ECR images"

  event_pattern = jsonencode({
    source      = ["aws.inspector2"]
    detail-type = ["Inspector2 Finding"]
    detail = {
      severity = ["CRITICAL"]
      resources = {
        type = ["AWS_ECR_CONTAINER_IMAGE"]
      }
    }
  })
}
```

---

## Secrets Detection in Image Layers

Images occasionally contain accidentally embedded secrets — hardcoded API keys, certificates, and credentials introduced during development or by misconfigured build steps. Scan for embedded secrets at build time and as part of continuous registry scanning.

**Trivy secret scanning for container images:**

```bash
# Scan a container image for embedded secrets
trivy image \
  --scanners secret \
  --format json \
  --output image-secret-scan.json \
  your-app:latest

# Common findings to investigate:
# - AWS access keys (AKIA...)
# - GitHub personal access tokens (ghp_...)
# - Private keys (-----BEGIN RSA PRIVATE KEY-----)
# - Database connection strings with passwords
```

**Multi-stage build to prevent secret inclusion:**

```dockerfile
# CORRECT: Multi-stage build — build secrets never reach runtime image
FROM node:20-alpine AS builder

# Mount secret at build time — never written to image layers
RUN --mount=type=secret,id=npm_token \
    NPM_TOKEN=$(cat /run/secrets/npm_token) \
    npm config set //registry.npmjs.org/:_authToken=${NPM_TOKEN} \
    && npm ci \
    && npm run build

# Production stage — copy only compiled output, no build dependencies or secrets
FROM gcr.io/distroless/nodejs20-debian12 AS runtime
COPY --from=builder /app/dist /app/dist
USER nonroot
EXPOSE 3000
CMD ["/app/dist/server.js"]
```

---

## Admission Control — Enforcing Registry Policy in Kubernetes

Registry hardening at the source is necessary but incomplete without enforcement at the deployment layer. Kubernetes admission controllers can block deployments that violate registry security policy.

**Kyverno policy — enforce signed images from approved registries only:**

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-signed-images-from-approved-registries
  annotations:
    policies.kyverno.io/title: Require Signed Images from Approved Registries
    policies.kyverno.io/description: |
      All container images must be pulled from approved internal registries
      and must have a valid Cosign signature. This prevents supply chain attacks
      via public registry dependency confusion and tampered image injection.
spec:
  validationFailureAction: Enforce
  background: false
  rules:
    - name: check-registry
      match:
        any:
          - resources:
              kinds: [Pod]
              namespaces: ["production", "staging"]
      validate:
        message: "Images must be from an approved internal registry"
        pattern:
          spec:
            containers:
              - image: "registry.internal/* | staging-registry.internal/*"

    - name: verify-image-signature
      match:
        any:
          - resources:
              kinds: [Pod]
              namespaces: ["production"]
      verifyImages:
        - imageReferences:
            - "registry.internal/*"
          attestors:
            - entries:
                - keyless:
                    subject: "https://github.com/your-org/*/.github/workflows/*.yml@refs/heads/main"
                    issuer: "https://token.actions.githubusercontent.com"
                    rekor:
                      url: https://rekor.sigstore.dev
```

---

## Registry Security Hardening Checklist

Use this checklist to assess and improve the security posture of your container registry deployment.

### Access Control
- [ ] Workload identity (OIDC/managed identity) used for all pipeline-to-registry authentication; no long-lived static credentials
- [ ] Registry credentials are namespaced — push rights scoped to specific repositories, not the entire registry
- [ ] Separate credentials for push (CI) and pull (deployment); read-only pull credentials for all deployment environments
- [ ] Pull secrets in Kubernetes are stored as Secrets and bound to specific service accounts, not mounted globally
- [ ] Registry admin credentials are stored in a secrets manager (not in CI/CD variables or `.env` files)
- [ ] Developer workstations cannot push to production-promotion namespaces

### Image Integrity
- [ ] Tag immutability is enabled in all registries used for staging and production
- [ ] All images are signed with Cosign (keyless OIDC or organizational key) before promotion to staging
- [ ] Production deployments pull images by digest, not mutable tag
- [ ] Kubernetes admission controller (Kyverno or OPA Gatekeeper) enforces image signature verification
- [ ] Only images from approved internal registries can be deployed in production namespaces

### Vulnerability Management
- [ ] Vulnerability scan runs at build time (CI/CD pipeline) for all new images
- [ ] Registry-native continuous scanning (ECR Enhanced Scanning / ACR Defender for Containers / Harbor) is enabled
- [ ] Alerts are configured for new CRITICAL/HIGH findings in actively deployed images
- [ ] Image lifecycle policies automatically expire development and PR images
- [ ] Production-promoted images are retained for a minimum of 365 days for rollback and audit purposes

### Secrets and Data
- [ ] Multi-stage Docker builds are used to prevent build-time secrets from reaching runtime images
- [ ] Trivy (or equivalent) secret scanning is run against all images in CI pipeline
- [ ] No plaintext secrets, private keys, or PII in any image layers (verified by continuous scanning)

### Audit and Compliance
- [ ] Registry access logs are forwarded to SIEM (push, pull, tag, delete events)
- [ ] Image push events trigger a compliance record update (SBOM attached to registry image)
- [ ] Image provenance (SLSA) attestations are attached to registry images alongside signatures
- [ ] Registry configuration (ACLs, lifecycle rules, scanning config) is managed as IaC and version-controlled

---

## Cross-References

| Topic | Related Document |
|-------|-----------------|
| Image signing and verification | [Secure CI/CD Framework](framework.md) |
| Pipeline secret management | [Secure CI/CD Best Practices](best-practices.md) |
| SBOM generation and attachment | [Software Supply Chain Security Framework](../../software-supply-chain-security-framework/docs/sbom-guide.md) |
| Artifact signing with Cosign | [Software Supply Chain Security Implementation](../../software-supply-chain-security-framework/docs/implementation.md) |
| Kyverno and OPA admission control | [Cloud Security DevSecOps](../../cloud-security-devsecops/docs/framework.md) |
| Pipeline templates with image scanning | [Secure Pipeline Templates](../../secure-pipeline-templates/README.md) |
