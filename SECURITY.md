# Security policy

## Supported versions

| Version | Security support | End of support |
|---|---|---|
| 1.x | Supported from the first 1.0.0 release | 2031-11-30, or five years after the first 1.0.0 release if later |
| Earlier releases | Unsupported | — |

## Reporting a vulnerability

Use [GitHub's private vulnerability reporting form](https://github.com/hutsebautvictor-star/reportaudit-lab/security/advisories/new).
Include the affected version, the observed impact and any evidence or suggested fix.
Keep secrets and personal data out of the report. Please keep the report private while we investigate.

## Response and disclosure

We aim to acknowledge reports within three business days and assess them within ten business days.
We aim to coordinate the fix and disclosure within 90 days, and will credit reporters who wish to be named.
Please keep any testing within systems you own or have permission to test, and avoid accessing personal data or disrupting service.

## Verifying releases

Starting with v1.0.0, release assets will include the source archive, a CycloneDX SBOM, SHA-256 checksums and Sigstore attestations.
Download the assets for the same tag, then run:

~~~bash
sha256sum -c SHA256SUMS
gh attestation verify reportaudit-1.0.0.tar.gz --repo hutsebautvictor-star/reportaudit-lab
gh attestation verify reportaudit-1.0.0.tar.gz --repo hutsebautvictor-star/reportaudit-lab \
  --predicate-type https://cyclonedx.org/bom
~~~
