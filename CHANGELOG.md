# Changelog

All notable changes to the Secure CI/CD Reference Architecture are documented here.
Format: `[version] — [date] — [summary of changes]`

---

## [Unreleased]

- [2026-04-07] README.md: Added "Related Frameworks" table linking to forensics-and-incident-response-framework (pipeline IR playbooks), software-supply-chain-security-framework, and secure-pipeline-templates with relationship descriptions
- [2026-04-07] README.md: Expanded Repository Structure listing to include all specialized docs (oidc-federation-guide.md, container-registry-security.md, pipeline-forensics-playbook.md, legacy-cicd-migration.md)
- [2026-04-07] README.md: Updated Book Series Overview link text to reference all five Techstream volumes
- Added CHANGELOG.md (this file) for version tracking
- Added "Learning Resources" section to README.md linking to Book 2, techstream-learn labs, and techstream.app
- docs/introduction.md: Completed Provenance glossary entry; added Lateral Movement in CI/CD Platforms section covering cross-pipeline secret access audit patterns, GitHub Actions GITHUB_TOKEN minimal permissions, GitLab CI_JOB_TOKEN allowlist, runner compromise and persistence with Falco detection rule, and supply chain pivot chain from repository to cloud (2026-04-07)


---

## [1.0.0] — 2026-05-17

### Added — Governance and Documentation

- `SECURITY.md` — security reporting policy and supported versions
- `CITATION.cff` — academic and industry citation metadata (CFF v1.2.0)
- `CODE_OF_CONDUCT.md` — Contributor Covenant v2.1
- `README.md` "Related Publications" section linking the TechStream article series

### Federal-standards alignment (this release)

- Continued alignment with Executive Order 14028 (Improving the Nation's Cybersecurity)
- Continued alignment with Executive Order 14306 (June 2025)
- Continued alignment with NIST SP 800-218 (SSDF) v1.1
- Acknowledgment of NIST SP 1800-44 (NCCoE DevSecOps Practices) preliminary draft, March 2026

### Related publications referenced in this release

  - "The 4-Phase DevSecOps Transformation" (Medium, April 2026)
  - "The Four Layers of Software Supply Chain Integrity" (Medium, May 2026)

### Changed

- Documentation cross-references updated to reflect the public TechStream framework portfolio at https://github.com/sotille

## [1.0.0] — 2024-01-15

- Initial public release of the Secure CI/CD Reference Architecture
- Core framework documentation: introduction, architecture, framework, implementation, best-practices, roadmap
- STRIDE threat model for CI/CD pipelines with attack tree analysis
- OIDC federation guide for GitHub Actions, GitLab CI, Jenkins, and Azure Pipelines across AWS, Azure, and GCP
- Container registry security controls documentation
- AI-assisted development security guidance
- Legacy CI/CD migration guide for teams adopting secure pipeline patterns
- Pipeline forensics playbook for investigating compromised CI/CD environments
- Apache 2.0 license and contribution guidelines
