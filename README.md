<p align="center">
  <a href="https://techstream.app">
    <img src="https://techstream.app/images/techstream-icon.svg" width="72" height="72" alt="TechStream" />
  </a>
</p>

# Secure CI/CD Reference Architecture

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.0.0-green.svg)](https://github.com/techstream/secure-ci-cd-reference-architecture)
[![Documentation](https://img.shields.io/badge/docs-comprehensive-brightgreen.svg)](docs/)
[![Maintained](https://img.shields.io/badge/Maintained-yes-green.svg)](https://github.com/techstream/secure-ci-cd-reference-architecture)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

A comprehensive reference architecture for designing, implementing, and operating secure Continuous Integration and Continuous Delivery (CI/CD) pipelines. This repository provides threat models, architecture patterns, security controls, tool-specific implementation guides, and a maturity model for teams seeking to harden their software delivery infrastructure against modern attack vectors.

---

## Overview

CI/CD pipelines have become a primary attack surface for sophisticated adversaries. Supply chain attacks, credential theft through misconfigured pipeline secrets, malicious dependency injection, and pipeline privilege escalation are no longer theoretical risks — they are documented, real-world incidents affecting organizations of every size and industry.

This reference architecture addresses the full spectrum of CI/CD security challenges: from securing source code repositories and build environments to hardening artifact stores, enforcing deployment controls, and maintaining comprehensive audit trails for compliance. It provides concrete, implementable patterns rather than abstract principles, with specific guidance for GitHub Actions, GitLab CI, and Jenkins.

The architecture is platform-informed but not platform-locked. Every security pattern described here can be adapted to any major CI/CD platform with minor configuration changes.

---

## Scope

This reference architecture covers:

- **Source code security** — branch protection, commit signing, code review enforcement, and pre-commit hooks
- **Build environment security** — runner/agent hardening, ephemeral build environments, and dependency isolation
- **Secrets management** — detection, injection, rotation, and audit of pipeline secrets and credentials
- **Artifact security** — image scanning, artifact signing, SBOM generation, and repository access controls
- **Deployment security** — environment segregation, progressive delivery strategies, and deployment approval gates
- **Pipeline identity and access management** — least-privilege pipeline tokens, OIDC federation, and workload identity
- **Compliance** — SOC 2, PCI-DSS, and ISO 27001 control mapping for CI/CD environments
- **Audit and observability** — comprehensive pipeline logging, anomaly detection, and forensic capability

### Out of Scope

This reference architecture does not cover runtime application security monitoring (RASP), WAF configuration, or network perimeter security beyond pipeline network segmentation. For runtime security, refer to the companion [DevSecOps Framework](../devsecops-framework/) repository.

---

## Audience

| Role | Primary Documents |
|---|---|
| Security Architects | [Architecture](docs/architecture.md), [Framework](docs/framework.md) |
| Platform / DevOps Engineers | [Implementation](docs/implementation.md), [Best Practices](docs/best-practices.md) |
| Security Engineers | [Framework](docs/framework.md), [Best Practices](docs/best-practices.md) |
| Engineering Managers | [Introduction](docs/introduction.md), [Roadmap](docs/roadmap.md) |
| Compliance / Audit Teams | [Framework](docs/framework.md) (Compliance section), [Roadmap](docs/roadmap.md) |
| Developers | [Best Practices](docs/best-practices.md), [Implementation](docs/implementation.md) |

---

## Table of Contents

- [Overview](#overview)
- [Scope](#scope)
- [Audience](#audience)
- [How to Use This Reference](#how-to-use-this-reference)
- [Documentation](#documentation)
  - [Introduction](docs/introduction.md)
  - [Architecture](docs/architecture.md)
  - [Framework](docs/framework.md)
  - [Implementation](docs/implementation.md)
  - [Best Practices](docs/best-practices.md)
  - [Roadmap](docs/roadmap.md)
- [Repository Structure](#repository-structure)
- [Contributing](#contributing)
- [License](#license)

---

## How to Use This Reference

This repository is designed to be used in two ways:

### 1. As a Learning Resource

Read the documentation sequentially to build a complete understanding of secure CI/CD design:

1. Start with the **[Introduction](docs/introduction.md)** to understand the threat landscape, real-world breach patterns, and the STRIDE threat model applied to CI/CD pipelines.
2. Review the **[Architecture](docs/architecture.md)** document to understand the reference architecture's components, security zones, and Mermaid-diagrammed pipeline flows.
3. Study the **[Framework](docs/framework.md)** for the full security controls catalog, tool integrations (SAST, DAST, SCA, secrets detection, image scanning), and compliance mappings.
4. Use the **[Implementation](docs/implementation.md)** guide when you are ready to apply the patterns to GitHub Actions, GitLab CI, or Jenkins pipelines.
5. Keep **[Best Practices](docs/best-practices.md)** open as a reference checklist during design reviews and pipeline audits.
6. Use the **[Roadmap](docs/roadmap.md)** to plan your phased adoption and track maturity progression.

### 2. As an Operational Reference

Use specific sections as targeted reference material during:

- **Pipeline design reviews** — Architecture diagrams and security zone patterns
- **Security gate configuration** — Framework section on SAST/DAST/SCA thresholds and break-the-build criteria
- **Incident investigation** — Introduction's breach examples and threat model inform forensic analysis
- **Compliance audits** — Framework compliance mapping tables (SOC 2, PCI-DSS, ISO 27001)
- **New team onboarding** — Best practices document provides a self-contained guide for developers

---

## Documentation

| Document | Description | Audience |
|---|---|---|
| [Introduction](docs/introduction.md) | CI/CD threat model, attack vectors, breach examples, key concepts | All stakeholders |
| [Architecture](docs/architecture.md) | Secure pipeline architecture, zero-trust design, environment segregation | Architects, Platform Engineers |
| [Threat Model](docs/threat-model.md) | STRIDE analysis, MITRE ATT&CK CI/CD scenarios, control-to-threat mapping | Security Engineers, Architects |
| [Framework](docs/framework.md) | Security controls, SAST/DAST/SCA, secrets, signing, compliance mapping | Security Engineers, DevOps leads |
| [Pipeline Forensics Playbook](docs/pipeline-forensics-playbook.md) | Investigation procedures for pipeline compromise: evidence preservation, root cause analysis, blast radius assessment, artifact integrity verification | Security Engineers, Incident Responders |
| [Legacy CI/CD Migration](docs/legacy-cicd-migration.md) | Migration guide from Jenkins, Bamboo, and TeamCity to secure modern pipeline architecture; platform comparison, secrets migration, validation checklist | Platform Engineers, Architects |
| [Implementation](docs/implementation.md) | GitHub Actions, GitLab CI, Jenkins implementation guides; runner hardening | Platform Engineers, DevOps |
| [Best Practices](docs/best-practices.md) | 25+ best practices across source, build, test, deploy, secrets, access control | All engineering roles |
| [Roadmap](docs/roadmap.md) | Phased 0-180 day roadmap, maturity model, metrics, toolchain evolution | Leadership, Program Managers |

---

## Repository Structure

```
secure-ci-cd-reference-architecture/
├── README.md                          # This file
├── LICENSE                            # Apache 2.0 license
└── docs/
    ├── introduction.md                # Threat landscape, attack vectors, breach examples
    ├── architecture.md                # Reference architecture with Mermaid diagrams
    ├── threat-model.md                # STRIDE analysis, ATT&CK CI/CD scenarios, control mapping
    ├── framework.md                   # Security controls framework and compliance mapping
    ├── oidc-federation-guide.md       # Keyless authentication with GitHub Actions, GitLab CI
    ├── container-registry-security.md # Registry hardening, image signing, policy enforcement
    ├── pipeline-forensics-playbook.md # Incident investigation: evidence preservation, blast radius
    ├── legacy-cicd-migration.md       # Migration from Jenkins, Bamboo, TeamCity
    ├── implementation.md              # Platform-specific implementation guides
    ├── best-practices.md              # 25+ best practices by security domain
    └── roadmap.md                     # Phased roadmap and maturity model
```

### Related Frameworks

| Framework | Relationship |
|-----------|-------------|
| [forensics-and-incident-response-framework](../forensics-and-incident-response-framework/) | Extends pipeline-forensics-playbook.md with full IR playbooks (PL-01–PL-08), evidence chain of custody, and legal hold procedures for pipeline compromise investigations |
| [software-supply-chain-security-framework](../software-supply-chain-security-framework/) | Covers SLSA, SBOM, and artifact signing in depth; complements this framework's supply chain controls |
| [secure-pipeline-templates](../secure-pipeline-templates/) | Provides ready-to-use GitHub Actions and GitLab CI templates implementing the controls defined in this architecture |

---

## Learning Resources

The Techstream Book Series and hands-on lab companion extend the concepts in this framework with structured learning, exercises, and configuration walkthroughs.

- **[Book 2: Securing CI/CD & the Software Supply Chain](https://www.techstream.app/learn)** — The primary book volume aligned with this framework. Covers pipeline threat modeling, OIDC keyless authentication, artifact integrity, pipeline forensics, and real-world breach case studies including SolarWinds, Codecov, and PyTorch.
- **[Hands-On Labs (techstream-learn/book-2-cicd-supply-chain/)](https://www.techstream.app/learn)** — Practical exercises including STRIDE threat modeling for CI/CD pipelines, configuring OIDC federation for GitHub Actions, and detecting secrets in pipeline logs.
- **[Book Series Overview (VOLUMES.md)](../techstream-books/VOLUMES.md)** — Index of all five Techstream volumes covering DevSecOps foundations, supply chain security, cloud security, release governance, and AI and agentic systems security.
- **[Techstream Platform](https://www.techstream.app)** — The central portal for all Techstream frameworks, documentation, and learning resources.

---

## Contributing

Contributions are welcome and encouraged. The threat landscape and tooling ecosystem evolve rapidly, and this reference architecture is maintained as a living document.

### Contribution Process

1. **Fork the repository** and create a descriptively named branch.
2. **Follow the document structure** — maintain the existing heading hierarchy and table formatting conventions.
3. **Be specific** — avoid vague guidance. All recommendations must include concrete implementation steps or configuration examples.
4. **Cite sources** — when referencing CVEs, breach incidents, or compliance requirements, include references.
5. **Submit a pull request** with a clear summary of changes, the rationale, and any related issues.

### What We Welcome

- New platform-specific implementation guides (Azure DevOps, CircleCI, Tekton, ArgoCD)
- Updated threat model entries reflecting new attack patterns
- Additional compliance mappings (FedRAMP, HIPAA, GDPR)
- Tool-specific configuration examples and sample pipeline YAML
- Corrections to outdated tool versions, deprecated APIs, or changed compliance requirements

---

## License

Copyright 2024 Techstream

Licensed under the Apache License, Version 2.0. See the [LICENSE](LICENSE) file for the full license text.
