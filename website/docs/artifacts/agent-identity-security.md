# Gen AI Agent Identity Security Reference Architecture Framework

```
"Gen AI Agent Identity Security Reference Architecture Framework"

Authors: Pralay Desai, Electronic Arts, James Ferguson

Agentic Community Contributors

Copyright © 2025 Agentic Community
Licensed under CC BY-SA 4.0
Individual authors retain attribution rights
```

# **Purpose**

This framework defines identity-centric controls for Gen AI agents, mapping security requirements to each agent component and to end-to-end flows. It emphasizes Zero Trust, least privilege, short-lived credentials, privacy-by-design, and continuous monitoring to reduce risks like impersonation, data exfiltration, and abuse.


# **Core Principles**

1.** Zero Trust by Default**

Every interaction—between users, systems, and services—must be verified. Nothing is trusted automatically, even within the same network. Each step of communication (human ↔ app, app ↔ backend, agent ↔ tools/data) requires authentication and authorization.

**2. Least Privilege Access**

Users and agents get only the permissions needed for their tasks. Access is denied by default and granted only for specific, approved purposes. This reduces damage if credentials are compromised.

**3. Short-Lived Credentials**

Use temporary credentials that expire quickly and rotate often. This limits exposure if tokens or keys are leaked. Example: short-lived OAuth or mTLS tokens that auto-renew securely.

**4. Strong and Verifiable Identity**

Every user, service, and AI agent must have a unique, verifiable identity. Service identities should be cryptographically verifiable using systems like SPIFFE/SPIRE or signed tokens, ensuring authenticity and preventing spoofing.

**5. Separation of Duties**

Separate who decides access (Policy Decision Point) from who enforces it (Policy Enforcement Point). Keep secrets and runtime environments isolated to avoid privilege overlap or misuse.

**6. Comprehensive Auditability**

All identity-related actions must be logged securely and made tamper-evident. These logs should provide a clear picture of who did what, when, and why—enabling accountability and quick detection of anomalies.

**7. Privacy and Safety by Design**

Protect personal and sensitive data through redaction, minimization, and encryption. Ensure AI prompts and data flows adhere to privacy and ethical guidelines, including guardrails to prevent data leaks or unsafe outputs.

**Additional Identity Security Principles**

**8. Context-Aware Access**

Access should adapt to context—such as device posture, user location, time, or behavior. For example, deny access from unknown devices or unusual networks even if credentials are valid.

**9. Purpose-Based Data Usage**

Data access should always align with the intended, approved purpose. AI agents and users must declare their purpose before accessing data, and policies must enforce that declared purpose.

**10. Delegated and Impersonated Access with Consent**

When an AI agent acts on behalf of a human, it must first obtain explicit, time-bound consent. All impersonated actions must be visible to the human and fully auditable.

**11. Continuous Identity Assurance**

Identity verification shouldn’t stop after login. Systems should revalidate user and agent behavior throughout sessions—detecting anomalies like sudden location changes or abnormal activity.

**12. Defense in Depth**

Layer multiple controls—authentication, authorization, encryption, monitoring—so a single failure doesn’t lead to compromise. Each layer independently protects against misuse or breach.

**13. Resilience and Revocation**

Enable quick revocation of credentials, sessions, or impersonation rights if a threat is detected. Ensure systems recover gracefully and securely after compromise.

Architecture Diagram

![](https://github.com/user-attachments/assets/4be643bd-7062-4e08-b031-35321a57a4e8)

Request Flow Diagram


![](https://github.com/user-attachments/assets/aa3267f3-875c-4f9b-b6f6-a033f7a01e6e)






## **Components & Identity Security Requirements**


## **Identity & Access Layer (IdP/SSO)**

• AuthN: OIDC/OAuth 2.1; MFA/WebAuthn; device posture checks; step-up for risk.

• AuthZ: Central RBAC/ABAC with PDP; scoped tokens and policy versioning.

• Defaults: Deny unauthenticated; token TTL ≤ 15m; refresh rotation; cookie HttpOnly/Secure/SameSite.

• Standards: OAuth 2.1, OIDC, FIDO2/WebAuthn, NIST 800-63.

• Guardrails: Phishing-resistant login; replay protection (DPoP/PoP); session anomaly detection.


## **Frontend (UI/Chat/API Gateway – PEP)**

• AuthN: Validate OIDC/OAuth 2.1 tokens (iss/aud/exp/nbf); TLS 1.3 everywhere.

• AuthZ: Coarse-grained PEP at gateway; route-based scopes; quota & rate limits per subject.

• Defaults: Schema validation; deny oversized prompts/uploads; strict CORS/CSRF.

• Standards: JWT with RS256/ES256; OWASP ASVS & API Security Top 10.

• Guardrails: Input sanitization; prompt pre-filters; DLP on uploads; bot/automation detection.


## **Orchestrator / Router**

• AuthN: Validates caller tokens; attaches service identity (mTLS/JWT) to downstream calls.

• AuthZ: Purpose binding for memory & tools; policy checks with PDP per action.

• Defaults: Deny unknown tools/skills; allow-list external endpoints; concurrency caps.

• Standards: OAuth 2.1 service flows; Zero Trust (NIST SP 800-207).

• Guardrails: Prompt isolation between tenants/sessions; circuit breakers; red-team tested system prompts.


## **Agent Runtime – Components of Agents**

• AuthN: mTLS between components; SPIFFE/SPIRE SVIDs or signed service tokens.

• AuthZ: Capability tokens per component (planner, tools, memory, RAG); sandbox untrusted tools.

• Defaults: Memory and tool access are deny-by-default; strict IPC schemas.

• Standards: OAuth 2.1, SPIFFE/SPIRE, TLS 1.3, secure IPC patterns.

• Guardrails: Integrity & replay protection; egress allow-lists; component health & anomaly checks.


## **Planner**

• AuthN: Accepts only authenticated orchestration requests (mTLS/service token).

• AuthZ: Can request tools/memory only via policy-approved interfaces.

• Defaults: No direct data access; read-only planning by default.

• Guardrails: Token budget limits; prevent tool invocation loops; log plan diffs.


## **Tools Adapter / Skills Broker**

• AuthN: Per-tool credentials are short-lived & scoped; secure secret retrieval via KMS/HSM.

• AuthZ: Tool scopes per tenant/use case; explicit allow-list of functions and destinations.

• Defaults: Deny new tools until reviewed; sandbox untrusted tools.

• Standards: OAuth 2.1 client credentials / token exchange (RFC 8693); signed webhooks.

• Guardrails: Egress proxy with DLP; output validation; rate & concurrency limits.


## **Memory Store (Short/Long-Term)**

• AuthN: Service identity (mTLS/SVID); client-bound tokens for sessions.

• AuthZ: Row/column/namespace ACL; tenant separation; purpose-limited writes/reads.

• Defaults: Encrypt at rest; deny cross-tenant reads; retention limits by policy.

• Standards: AES-256 at rest, TLS 1.3 in transit; privacy frameworks (ISO/IEC 27555).

• Guardrails: PII redaction; data minimization before write; differential privacy where applicable.


## **Retrieval/RAG Index**

• AuthN: Signed requests with scoped tokens; signed URLs for artifacts.

• AuthZ: Query-time masking; context window filters by subject & purpose.

• Defaults: No default collections; explicit opt-in; max context size caps.

• Standards: Attribute-based filters; searchable encryption patterns.

• Guardrails: DLP scanning of retrieved chunks; lineage tags and watermarks in responses.


## **Reasoner / LLM**

• AuthN: Accepts inputs only via authenticated/runtime-authorized channels.

• AuthZ: Tool use gated by PEP; safety policies enforced in-context.

• Defaults: Safe policy prompts; blocked capabilities by default (e.g., file system/network).

• Standards: Content safety policies; model spec guardrails; inference isolation.

• Guardrails: Jailbreak/indirect injection detection; toxicity filters; human-in-the-loop for high risk.


## **Policy Decision Point (PDP) & Policy Store**

• AuthN: mTLS/service identity; request signing.

• AuthZ: Central decisioning for RBAC/ABAC/capabilities; versioned policies; approvals.

• Defaults: Deny on policy evaluation errors; audit all decisions.

• Standards: OPA/Rego (as applicable); XACML/ALFA patterns; NIST 800-207.

• Guardrails: Break-glass policies with alerts; regression tests for policy changes.


## **Secrets & Key Management (KMS/HSM)**

• AuthN: Strong service auth to KMS/HSM; attestation before key use where possible.

• AuthZ: Least-privilege key grants; per-tenant key material; envelope encryption.

• Defaults: No plaintext secrets in code/prompts/env; rotation & revocation SLAs.

• Standards: FIPS 140-2/3 HSM; AES-256; RSA/ECC best practices.

• Guardrails: Access anomaly alerts; dual control for key exports; tamper-evident logging.


## **Data Access Broker**

• AuthN: STS/short-lived OAuth tokens; signed URLs; client binding (DPoP/PoP).

• AuthZ: Row/column security; query allow-lists; purpose constraints.

• Defaults: Deny-by-default; masking/redaction by default for sensitive fields.

• Standards: TLS 1.3; privacy regulations (GDPR/CCPA) alignment.

• Guardrails: DLP, watermarking; query cost/volume limits; exfil alerts.


## **Observability & Audit**

• AuthN: Authenticated log/metrics pipelines; secure agents for telemetry.

• AuthZ: Redaction of sensitive data; role-based access for logs.

• Defaults: Immutable, time-synced logs; retention by policy; tenant scoping.

• Standards: OpenTelemetry; W3C trace context; CIS logging controls.

• Guardrails: Anomaly detection for AuthZ abuse; protected storage; incident triage hooks.


# **Identity-Critical Flows**


## **• End-User Login → IdP (OIDC/OAuth 2.1 + MFA/WebAuthn) → token issued → FE stores HttpOnly cookie → API GW validates.**

• Request Execution → FE→Gateway (PEP)→Orchestrator→Agent Components (mTLS/JWT)→Tools/Data (scoped, short-lived creds).

• On-Behalf-Of → Step-up MFA/consent → delegated token (RFC 8693) → auto-expire ≤30m → full audit trail.

• Memory Access → PEP→PDP purpose check → masked read/write → DLP post-check and lineage tags.


# **Extended Security Requirements**


## **Contextual Resource Access**

Contextual access control enforces security by validating context signals such as user location, device posture, network zone, and time of access. These signals determine whether access should be granted or restricted. This ensures higher security for sensitive operations by dynamically adjusting controls.

Example: A Gen AI agent denies access to sensitive training data if the request originates from an unmanaged device.


## **Attribute-Based Access Control (ABAC)**

ABAC policies leverage attributes of users, resources, and the environment to make fine-grained access decisions. Attributes can include role, clearance level, resource classification, or session risk score.

Example: A user with the attribute 'role=data_scientist' and clearance 'PII-read' may access anonymized datasets but not raw PII.


## **Purpose-Based Access Control (PBAC)**

Purpose-based access ensures that data or resources are accessed only when the purpose aligns with policy-approved activities. Every request is tagged with a declared purpose, and policies validate alignment before granting access.

Example: An AI agent can access patient data for 'treatment' purposes but is denied when the declared purpose is 'marketing'.


## **Resource-Bound Access Tokens (RBT)**

Resource-bound access tokens are cryptographically bound to a specific resource or context, preventing token misuse across other systems. They ensure that even if a token is stolen, it cannot be replayed against unauthorized resources.

Example: A short-lived JWT bound to a specific RAG collection cannot be reused to query unrelated datasets.


# **Appendix A – Examples of Advanced Security Controls**

• Contextual Access: Deny cross-border access attempts to sensitive datasets outside approved geographies.

• ABAC: Allow only agents tagged with 'confidential-project=true' to access internal research repositories.

• PBAC: Enforce purpose tags in API calls; reject access if the declared purpose does not match approved use cases.

• RBT: Issue resource-scoped tokens for each microservice call; reject replayed tokens at unrelated services.


# **Identity Security for Human Impersonation by Gen AI Agents**

Human impersonation by Gen AI agents introduces unique security risks. When agents act on behalf of a human, the system must enforce strict identity assurance, explicit consent, and auditable boundaries. These requirements prevent misuse of impersonation capabilities while preserving legitimate use cases such as delegated task execution.


## **Security Principles**

• Explicit Consent: Humans must grant informed, time-bound consent before impersonation begins.

• Least Privilege: Impersonated sessions inherit only the minimum privileges required for the delegated task.

• Transparency: All impersonated actions must be clearly visible to the human and logged for audit.

• Revocability: Humans must have the ability to revoke impersonation rights at any time.

• Accountability: Immutable logs and alerts ensure traceability of impersonated actions.


## **Security Requirements**

• Authentication (AuthN): Require strong step-up authentication (e.g., MFA/WebAuthn) before an agent begins impersonation.

• Authorization (AuthZ): Scope impersonation tokens narrowly, limiting them to predefined tasks or resources.

• Defaults: Impersonation sessions auto-expire within short time windows (e.g., ≤30 minutes).

• Guardrails: Notify the human of each impersonated action in real time and maintain detailed audit logs.

• Standards: Align impersonation flows with OAuth 2.1 'on-behalf-of' grants (RFC 8693) and NIST 800-63 digital identity assurance levels.


# **Appendix B – Examples of Human Impersonation Controls**

• An AI assistant impersonates a support agent to reset a customer password, but only after the human approves via MFA.

• An agent impersonates a project manager to schedule meetings, but cannot access the manager’s financial approvals.

• Each impersonated action (e.g., sending an email) triggers a notification to the human for transparency.

• Impersonation tokens expire after 20 minutes, requiring renewal with explicit human consent.


# **Practical Example – End-to-End Implementation**

1) Login & Context: The support agent signs in via OIDC/OAuth 2.1 with WebAuthn (MFA). Frontend captures context (managed device, corp network) and risk score.

2) Token Validation & PEP: API Gateway validates iss/aud/exp and enforces rate/quota, schema checks, and CSRF/CORS protections.

3) Purpose & Policy: The request is tagged purpose=customer_support_refund. Orchestrator calls PDP, which evaluates ABAC (role=csr, region allowed), PBAC (purpose matches policy), and contextual rules (device posture).

4) Scoped Credentials: Tools Adapter requests a short-lived Resource-Bound Token (RBT) from KMS/Data Broker scoped to orders:read and orders:refund for collection=orders_eu only.

5) Retrieval with Minimization: RAG fetch narrows to necessary fields (order_id, status, amount) with row/column ACL; guardrails scan retrieved chunks (DLP).

6) Human Impersonation: For email send as the human agent, system prompts step-up MFA and explicit consent; issues on-behalf-of token limited to send_email:refund_ack for 20 minutes.

7) Execution & Guardrails: Reasoner prepares refund; Guardrails check for policy/prompt violations; Orchestrator executes tool call using RBT; email sent with impersonation token.

8) Audit & Alerts: Observability records who/what/when/why (purpose, scopes, token IDs). Anomaly detection monitors unusual access or refund volumes.


## **Requirement Mapping**

• Contextual Resource Access → Steps 1 & 3 (device posture, network zone, risk).

• ABAC → Step 3 (role=csr, region=EU applied at PDP).

• Purpose-Based Access Control → Steps 3 & 8 (purpose=customer_support_refund).

• Resource-Bound Access Tokens → Step 4 (RBT scoped to orders_eu with orders:refund).

• Human Impersonation Controls → Step 6 (MFA, consent, OBO token with 20m TTL).


## **Practical Example Diagram**


![](https://github.com/user-attachments/assets/70456f10-4d0c-4388-8974-49943d4e874e)



# **Summary Table – Security Requirements per Component**

The table below provides a condensed view of key security requirements for each Gen AI agent component. It highlights Authentication (AuthN), Authorization (AuthZ), and advanced access models (ABAC, PBAC, RBT, Contextual Access).

| Component                    | AuthN                                           | AuthZ / Access Control                 | Advanced Controls                           |
|------------------------------|-------------------------------------------------|----------------------------------------|---------------------------------------------|
| IdP / SSO                    | OIDC/OAuth 2.1, MFA/WebAuthn, Device binding    | Central RBAC with PDP                  | Contextual access, step-up auth             |
| Frontend (PEP)               | Validate JWT, TLS 1.3, CSRF protection          | PEP with scopes, deny-by-default       | ABAC, PBAC, schema validation, DLP          |
| Orchestrator                 | Service JWT/mTLS                                | PDP evaluation                         | Purpose binding, ABAC+PBAC                  |
| Agent Runtime                | SPIFFE/SPIRE SVIDs, mTLS                        | Capability tokens per component        | Sandbox isolation, integrity checks         |
| Planner                      | Authenticated requests                          | Policy-limited tool/memory requests    | Loop/budget limits                          |
| Tools Adapter                | Short-lived creds from KMS                      | Scoped tool access per tenant          | RBT, DLP, rate limiting                     |
| Memory Store                 | MTLS, PoP tokens                                | Namespace/row/col ACL, PBAC            | Encryption, minimization, anomaly alerts    |
| Retrieval / RAG              | Signed scoped tokens, RBT                       | Query masking, ABAC filters            | PBAC enforcement, DLP scans                 |
| Reasoner / LLM               | Runtime-only authenticated access               | PEP-gated tool use                     | Policy prompts, jailbreak/PII filters       |
| PDP                          | mTLS, request signing                           | Central RBAC/ABAC/Capabilities         | PBAC, contextual checks                     |
| KMS / HSM                    | Service auth, attestation                       | Least privilege grants                 | Rotation, dual control, anomaly alerts      |
| Data Access Broker           | STS tokens, RBT                                 | Row/column security, PBAC              | Masking, DLP, watermarking                  |
| Observability & Audit        | Authenticated telemetry                         | RBAC on logs                           | Immutable logs, anomaly detection           |
| Egress Proxy / Guardrails    | n/a                                             | Allow-lists enforced                   | DLP, classifiers, watermarking              |
| Federation                   | OIDC/SAML signed assertions                     | Attribute→RBAC mapping                 | Contextual isolation, drift detection       |
| Human Impersonation          | Step-up MFA/WebAuthn                            | Scoped OBO token                       | Consent, PBAC, auditability                 |
| External SaaS                | OAuth 2.1 client creds                          | Per-SaaS scopes                        | RBT per SaaS, DLP, egress proxy             |
| MCP Host/Servers             | MTLS/service tokens                             | Registry of allowed tools/resources    | RBT per server, sandboxing                  |
