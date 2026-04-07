# Contributing to the Techstream Secure CI/CD Reference Architecture

Thank you for your interest in contributing. This repository provides a reference architecture and implementation guidance for building and hardening secure CI/CD pipelines across GitHub Actions, GitLab CI, Jenkins, Azure DevOps, and other platforms. Contributions that improve technical accuracy, expand platform coverage, and reflect the current state of CI/CD security tooling are welcome.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [What We Welcome](#what-we-welcome)
- [What We Do Not Accept](#what-we-do-not-accept)
- [How to Contribute](#how-to-contribute)
- [Documentation Standards](#documentation-standards)
- [Review Process](#review-process)
- [License](#license)

---

## Code of Conduct

All contributors are expected to engage professionally and constructively. Technical disagreements should focus on substance, not individuals. Contributions that are dismissive, personal, or unprofessional will not be reviewed.

---

## What We Welcome

- **Platform-specific implementation guidance** — detailed, accurate implementation guidance for CI/CD platforms not yet fully covered, or updates to existing platform guidance when platform APIs and features change.
- **Security control updates** — as new attack patterns emerge (e.g., pipeline injection techniques, new supply chain attack vectors) and new mitigations become available, updates to the security control catalog are valuable.
- **New tooling references** — the CI/CD security tooling landscape evolves quickly. If an important tool or category is missing, additions with accurate technical descriptions are welcome.
- **Threat model additions** — new CI/CD threat scenarios that represent real-world attack patterns documented in public disclosures.
- **Configuration examples** — working, accurate pipeline configuration snippets for security tools are among the most actionable contributions.
- **Compliance mapping corrections or extensions** — updates to control mappings against SOC 2, PCI-DSS, ISO 27001, NIST 800-53, or other relevant frameworks.

---

## What We Do Not Accept

- **Vendor promotional content** — all tool references must reflect accurate technical capability. Contributions that read as product marketing will not be accepted.
- **Untested configuration examples** — pipeline configuration snippets should reflect real-world usage and should be syntactically correct for the stated platform version.
- **Scope beyond CI/CD security** — contributions covering cloud infrastructure security, runtime security, or compliance automation belong in the appropriate Techstream repositories.
- **Major structural reorganization** without prior issue discussion.

---

## How to Contribute

### Reporting Issues

Use GitHub Issues for:
- Outdated tool versions or deprecated configuration patterns
- Missing platform coverage
- Technical inaccuracies in threat models or security control descriptions
- Gaps in compliance mappings

### Submitting Pull Requests

1. Fork the repository and create a branch from `main` with a descriptive name.
2. Make your changes following the documentation standards below.
3. Verify that all code blocks are syntactically correct for the stated platform and version.
4. Open a pull request with a clear description of the change, the affected sections, and any references for technical claims.
5. Respond to review feedback within a reasonable timeframe.

---

## Documentation Standards

**Tone and Style**
- Professional, direct, and technical. Written for security architects and platform engineers.
- Avoid marketing language. Tool descriptions should be accurate capability statements.
- Use active voice and present tense.

**Technical Accuracy**
- Configuration examples must be accurate for the current stable version of the platform.
- Include version-specific caveats where behavior differs between versions.
- Validate YAML syntax before submitting pipeline examples.

**Markdown Formatting**
- ATX headers, fenced code blocks with language identifiers, relative internal links.
- Mermaid diagrams for architectural flows and pipeline stage diagrams.
- Tables for structured tool comparisons and control mappings.

**Code Examples**
All pipeline configuration examples (GitHub Actions YAML, GitLab CI YAML, Jenkinsfile) must:
- Be syntactically valid for the stated platform version
- Include inline comments explaining security-relevant configuration choices
- Use placeholder values (not real credentials, keys, or organization-specific values)

---

## Review Process

Pull requests are reviewed for technical correctness, scope alignment, documentation standards, and cross-repository consistency. Initial responses are typically provided within 5 business days.

---

## License

By contributing, you agree your contributions will be licensed under the [Apache License 2.0](LICENSE).
