# Security & Vulnerability Disclosure Policy

**Tool Name:** OpticHound  
**Last Updated:** October 25, 2026

---

## 1. Security Architecture & Commitments

OpticHound is built with the following core security assurances:

1. **Air-Gapped & Offline Operability**: OpticHound requires zero outbound internet access. It can operate in complete network isolation or airplane mode.
2. **Zero Inbound Remote Control**: OpticHound does not listen for incoming connections from the public internet. It only opens client sockets on the local subnet to probe authorized internal endpoints.
3. **Safe Memory Handling**: All socket buffers, banner strings, and HTTP headers are strictly size-capped and sanitized against memory exhaustion and buffer exploitation.
4. **Zero Third-Party Binary Bloat**: Built exclusively on standard library primitives with no precompiled binary blobs.

---

## 2. Reporting a Vulnerability

We welcome responsible security reports regarding potential vulnerabilities in OpticHound.

- **Security Contact**: `security@optichound.local` (or GitHub Security Advisories)
- **Response Commitment**: We acknowledge valid vulnerability submissions within **48 hours** and provide remediation patches within **14 calendar days**.
- **Safe Harbor**: If you conduct vulnerability research in good faith and comply with these guidelines, we will not pursue legal action against you under the Computer Fraud and Abuse Act (CFAA) or Indian Information Technology Act, 2000.
