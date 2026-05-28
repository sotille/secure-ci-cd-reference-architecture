# Canonical Pipeline Flow

This document defines the canonical secure CI/CD pipeline flow that this framework prescribes. Use it as the reference model when designing or auditing pipelines.

## Reference flow

```
Code  →  Build  →  SAST  →  SCA  →  Secrets Scan  →  Container Scan  →  SBOM  →  Signing  →  Deploy  →  Runtime Verify
```

## Stage-by-stage requirements

| Stage | Required activity | Alignment |
|---|---|---|
| Code | Branch protection, mandatory review, signed commits (optional) | EO 14028 §4(e)(i), NIST SSDF PS.1 |
| Build | Hermetic, reproducible where possible; build provenance | SLSA Level 2+; NIST SSDF PW.4 |
| SAST | Blocking on critical findings; baseline with VEX for false positives | NIST SSDF PW.7 |
| SCA | Direct + transitive dependency scan; license check | NIST SSDF PW.4; EO 14028 §4(e)(vii) |
| Secrets Scan | Pre-commit hook + CI scan; rotation on detection | NIST SSDF PW.6 |
| Container Scan | Image vulnerability + misconfiguration scan | CIS Benchmarks; NIST SP 800-190 |
| SBOM | CycloneDX or SPDX; queryable index | EO 14028 §4(e)(vii) |
| Signing | Sigstore/Cosign keyless signing; transparency log (Rekor) | SLSA; EO 14028 §4(e)(viii) |
| Deploy | Verified signature + provenance at admission | SLSA Level 3+ |
| Runtime Verify | Admission controller + periodic re-verification | EO 14306; NIST SP 1800-44 |

## Anti-patterns

- Sign artifacts but do not verify at deploy time → "digital provenance theater"
- Generate SBOM but do not build a queryable index → "compliance artifact factory"
- Treat SAST as advisory only → controls exist on paper but not in production

For practitioner-focused discussion of these anti-patterns, see the May 2026 Medium article "The Four Layers of Software Supply Chain Integrity."
