# Threat Model

This document covers two distinct trust contexts: the tool as deployed software, and the tool's detection engine as an analytical product.

## Trust Boundaries

- **Trusted:** only this project's own code.
- **Untrusted input:** every uploaded IAM export JSON file, without exception — including files from the project's own maintainer.
- **No persistence:** the backend is fully stateless by design. Uploaded files are processed entirely in memory and are never written to disk, logged, or retained after the response is sent. This eliminates several threat categories outright rather than mitigating them after the fact.

## Threats — Public Deployment

| # | Threat | Actor | Impact | Mitigation |
|---|---|---|---|---|
| T1 | User uploads real, unsanitized IAM data from a live production account | Careless legitimate user | Real ARNs/account IDs/role names briefly touch the server | Ephemeral-only processing, no disk writes, explicit UI warning against uploading real production data |
| T2 | Malicious or malformed JSON crafted to crash or exploit the parser | Random internet abuser | Denial of service, potential exploitation of a parsing bug | Strict `pydantic` schema validation, upload size cap, no `eval()`/unsafe deserialization anywhere in the parsing path |
| T3 | Someone uploads IAM data they obtained without authorization | Malicious actor | Tool becomes an unwitting recon aid for an active, unauthorized attack | Cannot be fully prevented (true of any offline analysis tool); mitigated by ephemeral-only processing (nothing is retained) and an explicit authorized-use disclaimer |
| T4 | Public demo abused for free compute / spam uploads | Random internet abuser | Availability, hosting cost | 5MB upload cap, no expensive persistent compute per request |
| T5 | XSS via crafted IAM principal/policy names rendered in the graph UI | Malicious upload with e.g. `<script>` in a role name | Client-side attack on other users of a public demo | All rendered fields go through React's default output encoding; Cytoscape.js labels are treated as data, not HTML |
| T6 | Ambiguity about whether this is an "exploitation" tool | Public perception / platform ToS | Reputational, possible takedown | Explicitly read-only: the engine never makes a live AWS API call that could modify or attack anything — it only analyzes user-provided static JSON |

## Threats — Detection Accuracy

| # | Threat | Impact |
|---|---|---|
| T7 | False negative — a real escalation path goes undetected | Worse than not having the tool at all: gives false confidence to a defender, or a tester misses a real path |
| T8 | False positive — a flagged path is actually blocked by a Service Control Policy (SCP) or permission boundary not visible to the engine | Erodes trust in tool output; documented honestly as a known v1 limitation rather than hidden |

**On T8 specifically:** v1 does not ingest AWS Organizations-level data (SCPs, permission boundaries), because a standard `iam:GetAccountAuthorizationDetails` export doesn't include it. Every finding should be verified against the account's actual SCP configuration before being treated as confirmed-exploitable. This is stated in the README and is a deliberate, disclosed scope boundary — not an oversight.

## Summary

The core design choice underlying most of these mitigations is architectural, not procedural: a stateless backend with no persistence layer removes entire categories of risk (T1, T4) by construction, rather than relying on policy or discipline to prevent misuse of stored data that simply doesn't exist.
