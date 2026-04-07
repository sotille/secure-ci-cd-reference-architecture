# OIDC Federation for CI/CD Pipelines

Long-lived credentials in CI/CD pipelines are one of the highest-risk secrets in a software organization. A compromised IAM key, service account JSON, or API token stored in CI secrets gives an attacker persistent access to cloud environments, artifact registries, and deployment targets — often with broad permissions accumulated over time.

OpenID Connect (OIDC) federation eliminates this risk by replacing long-lived credentials with short-lived, job-scoped tokens issued by the CI/CD platform's identity provider. This guide covers the mechanics of OIDC federation and provides production-ready configurations for GitHub Actions, GitLab CI, Jenkins, and Azure Pipelines across AWS, Azure, and GCP.

---

## How OIDC Federation Works

Traditional credential flow (problem):

```
Developer/Admin → creates long-lived IAM key → stores in CI secrets → pipeline uses key
                                                ↑
                                    Key persists forever; compromised if secrets leaked
```

OIDC federation flow (solution):

```
Pipeline job starts
      │
      ▼
CI platform issues a signed OIDC JWT token
      │ Token contains claims:
      │  - iss (issuer): https://token.actions.githubusercontent.com
      │  - sub (subject): repo:org/repo:ref:refs/heads/main
      │  - aud (audience): sts.amazonaws.com
      │  - workflow, run_id, environment, etc.
      │
      ▼
Pipeline exchanges OIDC token with cloud provider's STS
      │ Cloud verifies: Is this issuer trusted? Does the subject match policy conditions?
      │
      ▼
Cloud issues short-lived session credentials (15 min – 1 hour)
      │
      ▼
Pipeline uses credentials → credentials expire when job ends
```

The cloud provider trusts the CI platform's OIDC issuer because you configured an explicit trust relationship. The CI platform signs the JWT with a private key; the cloud provider verifies the signature using the public keys published at the issuer's JWKS endpoint.

**Key security properties:**
- No credential storage: tokens are not stored anywhere; they are requested fresh each job
- Short lifetime: credentials expire after the job (typically 15–60 minutes)
- Narrow scope: each job role has only the permissions needed for that job
- Cryptographically verifiable: the OIDC token is signed; it cannot be forged
- Revocable without rotation: disabling the trust relationship immediately prevents all new token issuance

---

## GitHub Actions → AWS

### Step 1: Create the OIDC Identity Provider in AWS

```hcl
# Terraform
data "tls_certificate" "github_actions" {
  url = "https://token.actions.githubusercontent.com/.well-known/openid-configuration"
}

resource "aws_iam_openid_connect_provider" "github_actions" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.github_actions.certificates[0].sha1_fingerprint]

  tags = {
    Name    = "github-actions-oidc"
    Purpose = "CI/CD pipeline OIDC federation"
  }
}
```

Or via AWS CLI:

```bash
aws iam create-open-id-connect-provider \
  --url https://token.actions.githubusercontent.com \
  --client-id-list sts.amazonaws.com \
  --thumbprint-list 6938fd4d98bab03faadb97b34396831e3780aea1
```

### Step 2: Create IAM Roles with Scoped Trust Policies

Create separate roles for each distinct set of permissions needed in your pipeline. Do not create one role with all permissions.

```hcl
# Role for build job (read-only registry access + ECR push for the specific repo)
resource "aws_iam_role" "github_build" {
  name = "github-build-${var.service_name}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = {
          Federated = aws_iam_openid_connect_provider.github_actions.arn
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          }
          StringLike = {
            # Restrict to specific repository; wildcard on ref allows any branch (acceptable for build)
            "token.actions.githubusercontent.com:sub" = "repo:${var.github_org}/${var.github_repo}:*"
          }
        }
      }
    ]
  })
}

# Role for production deployment (deploy to specific ECS service / EKS namespace only)
resource "aws_iam_role" "github_deploy_production" {
  name = "github-deploy-prod-${var.service_name}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = {
          Federated = aws_iam_openid_connect_provider.github_actions.arn
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
            # Lock to main branch only — no PR or feature branch can deploy to production
            "token.actions.githubusercontent.com:sub" = "repo:${var.github_org}/${var.github_repo}:ref:refs/heads/main"
            # Require a GitHub Actions environment named "production" (enables manual approval gate)
            "token.actions.githubusercontent.com:environment" = "production"
          }
        }
      }
    ]
  })
}
```

**Subject claim patterns for different scopes:**

| Scope | Subject Claim Pattern | Use Case |
|-------|----------------------|---------|
| Any ref in repo | `repo:org/repo:*` | Build, test, scanning jobs |
| Specific branch | `repo:org/repo:ref:refs/heads/main` | Staging deployment |
| Specific environment | `repo:org/repo:environment:production` | Production deployment (with approval gate) |
| Pull request | `repo:org/repo:pull_request` | PR security scanning (read-only) |
| Specific tag pattern | `repo:org/repo:ref:refs/tags/v*` | Release tagging |

### Step 3: GitHub Actions Workflow

```yaml
name: Build and Deploy

on:
  push:
    branches: [main]

permissions:
  contents: read
  id-token: write  # Required to request the OIDC JWT

jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write
      packages: write
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683

      - name: Configure AWS credentials (OIDC)
        uses: aws-actions/configure-aws-credentials@e3dd6a429d7300a6a4c196c26e071d42e0343502
        with:
          role-to-assume: arn:aws:iam::${{ vars.AWS_ACCOUNT_ID }}:role/github-build-${{ vars.SERVICE_NAME }}
          aws-region: us-east-1
          role-session-name: ${{ github.repository_owner }}-${{ github.run_id }}
          role-duration-seconds: 900  # 15 minutes — minimum required for build job

      - name: Build and push to ECR
        run: |
          aws ecr get-login-password | docker login --username AWS --password-stdin \
            ${{ vars.AWS_ACCOUNT_ID }}.dkr.ecr.us-east-1.amazonaws.com
          docker build -t ${{ vars.ECR_REGISTRY }}/${{ vars.SERVICE_NAME }}:${{ github.sha }} .
          docker push ${{ vars.ECR_REGISTRY }}/${{ vars.SERVICE_NAME }}:${{ github.sha }}

  deploy-production:
    needs: [build, security-scan]
    runs-on: ubuntu-latest
    environment: production  # Triggers manual approval gate
    permissions:
      contents: read
      id-token: write
    steps:
      - name: Configure AWS credentials for production deployment (OIDC)
        uses: aws-actions/configure-aws-credentials@e3dd6a429d7300a6a4c196c26e071d42e0343502
        with:
          # Separate role with only deployment permissions — not build permissions
          role-to-assume: arn:aws:iam::${{ vars.PROD_AWS_ACCOUNT_ID }}:role/github-deploy-prod-${{ vars.SERVICE_NAME }}
          aws-region: us-east-1
          role-session-name: deploy-${{ github.run_id }}-${{ github.run_attempt }}
          role-duration-seconds: 900

      - name: Deploy to ECS
        run: |
          aws ecs update-service \
            --cluster production-cluster \
            --service ${{ vars.SERVICE_NAME }} \
            --force-new-deployment
```

---

## GitHub Actions → Azure

### Step 1: Create Azure AD App Registration and Federated Credential

```bash
# Create App Registration
APP_ID=$(az ad app create --display-name "github-actions-${SERVICE_NAME}" --query appId -o tsv)
OBJECT_ID=$(az ad app show --id $APP_ID --query id -o tsv)

# Create Service Principal
az ad sp create --id $APP_ID

# Add federated credential for main branch deployments
az ad app federated-credential create \
  --id $OBJECT_ID \
  --parameters '{
    "name": "github-main-branch",
    "issuer": "https://token.actions.githubusercontent.com",
    "subject": "repo:org/payments:ref:refs/heads/main",
    "audiences": ["api://AzureADTokenExchange"],
    "description": "GitHub Actions OIDC for main branch deployments"
  }'

# Add federated credential for production environment
az ad app federated-credential create \
  --id $OBJECT_ID \
  --parameters '{
    "name": "github-production-environment",
    "issuer": "https://token.actions.githubusercontent.com",
    "subject": "repo:org/payments:environment:production",
    "audiences": ["api://AzureADTokenExchange"],
    "description": "GitHub Actions OIDC for production environment deployments"
  }'
```

Using Terraform:

```hcl
resource "azuread_application" "github_actions" {
  display_name = "github-actions-${var.service_name}"
}

resource "azuread_service_principal" "github_actions" {
  client_id = azuread_application.github_actions.client_id
}

resource "azuread_application_federated_identity_credential" "main_branch" {
  application_id = azuread_application.github_actions.id
  display_name   = "github-main-branch"
  issuer         = "https://token.actions.githubusercontent.com"
  subject        = "repo:${var.github_org}/${var.github_repo}:ref:refs/heads/main"
  audiences      = ["api://AzureADTokenExchange"]
}

resource "azuread_application_federated_identity_credential" "production" {
  application_id = azuread_application.github_actions.id
  display_name   = "github-production"
  issuer         = "https://token.actions.githubusercontent.com"
  subject        = "repo:${var.github_org}/${var.github_repo}:environment:production"
  audiences      = ["api://AzureADTokenExchange"]
}

# Assign role to the Service Principal
resource "azurerm_role_assignment" "deploy" {
  scope                = azurerm_resource_group.app.id
  role_definition_name = "Contributor"  # Scope further to specific resources in production
  principal_id         = azuread_service_principal.github_actions.object_id
}
```

### Step 2: GitHub Actions Workflow for Azure

```yaml
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683

      - name: Azure login via OIDC
        uses: azure/login@a65d910e8af852a8061c627c456678983e180302
        with:
          client-id: ${{ vars.AZURE_CLIENT_ID }}
          tenant-id: ${{ vars.AZURE_TENANT_ID }}
          subscription-id: ${{ vars.AZURE_SUBSCRIPTION_ID }}
          # No client-secret — using OIDC

      - name: Deploy to AKS
        uses: azure/k8s-deploy@v5
        with:
          namespace: production
          manifests: k8s/production/
          images: ${{ vars.ACR_REGISTRY }}/${{ vars.SERVICE_NAME }}:${{ github.sha }}
```

---

## GitHub Actions → GCP

### Step 1: Configure Workload Identity Federation in GCP

```bash
# Create Workload Identity Pool
gcloud iam workload-identity-pools create github-actions \
  --project="${PROJECT_ID}" \
  --location="global" \
  --display-name="GitHub Actions"

# Create OIDC Provider in the Pool
gcloud iam workload-identity-pools providers create-oidc github \
  --project="${PROJECT_ID}" \
  --location="global" \
  --workload-identity-pool="github-actions" \
  --display-name="GitHub OIDC" \
  --attribute-mapping="google.subject=assertion.sub,attribute.actor=assertion.actor,attribute.repository=assertion.repository" \
  --issuer-uri="https://token.actions.githubusercontent.com"
```

Using Terraform:

```hcl
resource "google_iam_workload_identity_pool" "github_actions" {
  workload_identity_pool_id = "github-actions"
  display_name              = "GitHub Actions"
  project                   = var.project_id
}

resource "google_iam_workload_identity_pool_provider" "github_oidc" {
  workload_identity_pool_id          = google_iam_workload_identity_pool.github_actions.workload_identity_pool_id
  workload_identity_pool_provider_id = "github-oidc"
  project                            = var.project_id

  attribute_mapping = {
    "google.subject"       = "assertion.sub"
    "attribute.actor"      = "assertion.actor"
    "attribute.repository" = "assertion.repository"
  }

  # Restrict to your GitHub organization only
  attribute_condition = "assertion.repository_owner == '${var.github_org}'"

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}

# Allow GitHub Actions to impersonate the service account
resource "google_service_account_iam_member" "github_actions_deploy" {
  service_account_id = google_service_account.deploy.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github_actions.name}/attribute.repository/${var.github_org}/${var.github_repo}"
}
```

### Step 2: GitHub Actions Workflow for GCP

```yaml
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683

      - id: auth
        name: Authenticate to GCP via OIDC
        uses: google-github-actions/auth@v2
        with:
          workload_identity_provider: projects/${{ vars.GCP_PROJECT_NUMBER }}/locations/global/workloadIdentityPools/github-actions/providers/github-oidc
          service_account: deploy-${{ vars.SERVICE_NAME }}@${{ vars.GCP_PROJECT_ID }}.iam.gserviceaccount.com

      - name: Deploy to GKE
        uses: google-github-actions/get-gke-credentials@v2
        with:
          cluster_name: production-cluster
          location: us-central1
```

---

## GitLab CI → AWS

GitLab CI supports OIDC federation using the `CI_JOB_JWT_V2` variable (GitLab 14.7+).

### Step 1: Create OIDC Provider for GitLab

```hcl
resource "aws_iam_openid_connect_provider" "gitlab" {
  url             = "https://gitlab.com"  # Or your self-hosted GitLab URL
  client_id_list  = ["https://gitlab.com"]
  thumbprint_list = ["b3dd7606d2b5a8b4a13771dbecc9ee1cecafa38a"]  # GitLab.com TLS cert thumbprint
}

resource "aws_iam_role" "gitlab_deploy" {
  name = "gitlab-deploy-${var.service_name}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = aws_iam_openid_connect_provider.gitlab.arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "gitlab.com:aud" = "https://gitlab.com"
        }
        StringLike = {
          # project_path:group/project:ref_type:branch:ref:main
          "gitlab.com:sub" = "project_path:${var.gitlab_group}/${var.gitlab_project}:ref_type:branch:ref:main"
        }
      }
    }]
  })
}
```

### Step 2: GitLab CI Pipeline

```yaml
# .gitlab-ci.yml
deploy-production:
  stage: deploy
  image: amazon/aws-cli:latest
  id_tokens:
    AWS_TOKEN:
      aud: https://gitlab.com
  script:
    - |
      # Exchange GitLab OIDC token for AWS credentials
      export $(aws sts assume-role-with-web-identity \
        --role-arn "arn:aws:iam::${AWS_ACCOUNT_ID}:role/gitlab-deploy-${SERVICE_NAME}" \
        --role-session-name "gitlab-${CI_JOB_ID}" \
        --web-identity-token "$AWS_TOKEN" \
        --duration-seconds 900 \
        --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' \
        --output text | awk '{print "AWS_ACCESS_KEY_ID="$1"\nAWS_SECRET_ACCESS_KEY="$2"\nAWS_SESSION_TOKEN="$3}')

      # Now use the short-lived credentials
      aws ecs update-service --cluster production-cluster --service $SERVICE_NAME --force-new-deployment
  only:
    - main
  environment:
    name: production
```

---

## Jenkins → AWS

Jenkins supports OIDC federation through the OpenID Connect Provider plugin or by using AWS STS directly with a token generated from the Jenkins OIDC plugin.

```groovy
// Jenkinsfile — OIDC-based AWS authentication
pipeline {
    agent { label 'ephemeral-runner' }

    stages {
        stage('Authenticate') {
            steps {
                withCredentials([
                    // Jenkins OIDC plugin generates a short-lived token
                    string(credentialsId: 'aws-oidc-role-arn', variable: 'ROLE_ARN')
                ]) {
                    script {
                        // Request OIDC token from Jenkins OIDC plugin
                        def oidcToken = generateOidcToken(audience: 'sts.amazonaws.com')

                        // Exchange for STS credentials
                        def credentials = sh(
                            script: """
                                aws sts assume-role-with-web-identity \
                                    --role-arn ${ROLE_ARN} \
                                    --role-session-name jenkins-${env.BUILD_NUMBER} \
                                    --web-identity-token ${oidcToken} \
                                    --duration-seconds 900 \
                                    --query 'Credentials' \
                                    --output json
                            """,
                            returnStdout: true
                        ).trim()

                        def creds = readJSON(text: credentials)
                        env.AWS_ACCESS_KEY_ID = creds.AccessKeyId
                        env.AWS_SECRET_ACCESS_KEY = creds.SecretAccessKey
                        env.AWS_SESSION_TOKEN = creds.SessionToken
                    }
                }
            }
        }

        stage('Deploy') {
            steps {
                sh 'aws ecs update-service --cluster production-cluster --service ${SERVICE_NAME} --force-new-deployment'
            }
        }
    }
}
```

**Alternative for Jenkins:** Use the [AWS Credentials Binding Plugin](https://plugins.jenkins.io/aws-credentials/) with IAM roles for EC2 if Jenkins runs on EC2 with an attached instance profile. This eliminates the need for OIDC entirely — the instance role provides credentials automatically.

---

## Azure Pipelines → Azure

Azure Pipelines supports native OIDC federation through service connections of type "Azure Resource Manager (Workload Identity federation)".

```yaml
# azure-pipelines.yml
trigger:
  branches:
    include: [main]

stages:
  - stage: Deploy
    condition: and(succeeded(), eq(variables['Build.SourceBranch'], 'refs/heads/main'))
    jobs:
      - deployment: DeployToProduction
        environment: production  # Approval gate configured in Azure DevOps Environments
        strategy:
          runOnce:
            deploy:
              steps:
                - task: AzureCLI@2
                  displayName: Deploy to AKS
                  inputs:
                    # Service connection uses Workload Identity Federation (OIDC) — no secret stored
                    azureSubscription: 'production-oidc-connection'
                    scriptType: bash
                    scriptLocation: inlineScript
                    inlineScript: |
                      az aks get-credentials --resource-group production-rg --name production-aks
                      kubectl set image deployment/$SERVICE_NAME \
                        app=$ACR_REGISTRY/$SERVICE_NAME:$(Build.SourceVersion)
```

---

## Security Controls for OIDC Federation

### Auditing OIDC Token Exchange

Every `AssumeRoleWithWebIdentity` call generates a CloudTrail event (AWS), an Azure AD sign-in log, or a GCP Cloud Audit Log. Configure alerting for:

| Alert Condition | Rationale |
|-----------------|-----------|
| Assumption from unexpected repository | A different repository attempting to assume your role |
| Assumption from unexpected branch | A feature branch assuming the production deployment role |
| Multiple assumptions in rapid succession | Replay attack or automated rotation anomaly |
| Assumption outside expected CI platform IP ranges | Token forwarded to unexpected infrastructure |

### Hardening Subject Claims

The subject claim (`sub`) is the primary binding between the CI job and the cloud role. Use the most restrictive subject claim pattern possible:

| Scenario | Subject Claim | Notes |
|----------|--------------|-------|
| Any job in repo | `repo:org/repo:*` | Too broad — only for dev/non-sensitive |
| Main branch only | `repo:org/repo:ref:refs/heads/main` | Good for staging |
| Tagged release | `repo:org/repo:ref:refs/tags/v*` | Release automation |
| Production environment (with approval) | `repo:org/repo:environment:production` | Best for production — requires manual approval |
| Specific workflow | `repo:org/repo:workflow:deploy.yml` | Adds workflow-level restriction |

### Preventing Privilege Escalation via OIDC

A compromised repository could modify the workflow to request a more privileged role. Prevent this:

1. **Protect pipeline files with CODEOWNERS** — `.github/workflows/` changes require security team approval
2. **Use separate roles for build and deploy** — build role cannot deploy; deploy role cannot build with elevated permissions
3. **Use GitHub Environments for production** — environment protection rules require manual approval and prevent unauthorized role assumption
4. **Monitor for new role additions in IaC** — any change to IAM role trust policies should trigger a security review

---

## Migrating from Long-Lived Credentials to OIDC

If your organization currently uses long-lived IAM keys or service account credentials in CI/CD secrets, follow this migration sequence:

| Step | Action |
|------|--------|
| 1 | Inventory all CI/CD secrets across all repositories that contain cloud credentials |
| 2 | For each credential, identify: which cloud account/project, what permissions, which pipeline jobs use it |
| 3 | Create scoped OIDC trust relationships (one per distinct permission set, not one per repository) |
| 4 | Update pipeline workflows to use OIDC authentication (use the templates in this guide) |
| 5 | Test in non-production environment first; validate all pipeline stages work with OIDC |
| 6 | Promote to production after validation |
| 7 | Disable the long-lived credential (do not delete immediately — monitor for 2 weeks for any unexpected usage alerts) |
| 8 | Delete the long-lived credential and remove from CI secrets store |

**Target state:** Zero long-lived cloud credentials stored in any CI/CD secrets store. All cloud access is via OIDC-federated short-lived tokens.

---

## Compliance Alignment

| Control | Framework | OIDC Federation Contribution |
|---------|-----------|------------------------------|
| No shared credentials | CIS Controls 5.4 | Each pipeline job gets a unique, non-sharable session |
| Time-limited credentials | NIST 800-53 IA-5(1) | All tokens have short expiry (15–60 minutes) |
| No long-lived static credentials | PCI-DSS Req 8.3, 8.6 | Eliminates persistent service account keys |
| Audit trail of credential use | SOC 2 CC6.1, CC8.1 | CloudTrail/Azure AD/GCP Audit Logs record every exchange |
| Least privilege | NIST 800-53 AC-6 | Each job role scoped to specific operations |
| Credential revocation | ISO 27001 A.8.2 | Trust relationship can be disabled instantly |

---

## Related Documents

- [Threat Model](threat-model.md) — CI/CD credential threats OIDC federation mitigates
- [Pipeline Forensics Playbook](pipeline-forensics-playbook.md) — Investigating suspected OIDC token abuse
- [Secure Pipeline Templates: Pipeline Identity and Credentials (Section 1)](../../secure-pipeline-templates/docs/hardening-checklist.md) — Hardening checklist items 1.1–1.6
- [Cloud Security: Zero Trust — Identity Pillar](../../cloud-security-devsecops/docs/zero-trust-architecture.md) — OIDC federation as workload identity control within zero trust architecture
- [DevSecOps Framework: Best Practices — OIDC Federation](../../devsecops-framework/docs/best-practices.md) — Practice: Use OIDC federation instead of long-lived credentials
