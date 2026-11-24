# AI-Assisted Web Vulnerability Assessment Workbench

## 1. Project Title

**AI-Assisted Web Vulnerability Assessment Workbench for the Contnental Fitness Gym Management System**

## 2. Background of the Study

Web applications hold personal, account, and transaction data. The Contnental Fitness Gym Management System is described in the project proposal as a Next.js and Supabase application for member registration, branch operations, attendance, and payment records. These features make access control, authentication, and secure data handling important assessment areas.

Security tools can collect many alerts, but an alert is an observation that needs review. Automated scanners may miss business logic issues or report conditions that do not apply to the target. A useful assessment workflow therefore needs to keep scanner evidence, technical validation, AI-written explanations, and assessor decisions separate.

The project uses OWASP's Web Security Testing Guide as a practical testing reference. OWASP describes automated tools as useful for breadth and repeatability, while application-specific testing and human judgment remain necessary for deeper issues. NIST SP 800-115 provides guidance for planning and conducting technical security assessments and analyzing findings.

## 3. Problem Statement

Student assessors can find it difficult to define an authorized scan scope, interpret raw scanner output, preserve evidence, and communicate risk to a non-specialist audience. A dashboard that turns alerts directly into confirmed vulnerabilities could mislead assessors and application owners.

The project addresses this problem by organizing target authorization, scanner report import, evidence review, assessor decisions, and reporting in one workspace. It is not intended to replace manual testing or professional judgment.

## 4. General Objective

To develop an accessible web application that helps authorized assessors organize web security assessment evidence, review scanner observations, record human verification decisions, and produce a clear report.

## 5. Specific Objectives

1. Record target name, owner contact, explicit authorization confirmation, and in-scope and out-of-scope URLs.
2. Reject non-HTTP URLs, embedded URL credentials, local or private destinations, and scope entries that do not match the target origin.
3. Import OWASP ZAP JSON reports while retaining the raw report separately from normalized observations.
4. Exclude imported finding instances outside the registered URL scope.
5. Allow assessors to mark each observation as Confirmed, Rejected, or Needs Review and assign a severity to confirmed findings.
6. Generate an HTML assessment report that counts only assessor-confirmed findings and states the assessment limitations.
7. Present service connectivity based on live health checks rather than configuration alone.

These objectives describe the version implemented in this repository. Automated scanning, AI analysis, independent technical validation, authentication, and PDF or Word report export are future work.

## 6. Proposed System

The workbench is a locally hosted assessment application. It stores target and assessment records in PostgreSQL. OWASP ZAP is included as a separate Docker service, but this version does not start scans. Assessors run ZAP separately and import its JSON report for review.

The application separates four kinds of information:

1. **Scanner observations:** the imported ZAP alert and raw report.
2. **AI interpretations:** not implemented in this version.
3. **Technical validation:** not performed by the platform in this version.
4. **Assessor decisions:** the review state, assigned severity, and assessor comment.

The interface retains visual cues from the source project: a near-black sidebar, orange primary actions, warm neutral background, light cards, and sans-serif typography. It uses short explanations and expandable technical details.

## 7. System Architecture

- **Frontend:** Next.js, React, and TypeScript. It provides the overview, target registration, ZAP JSON import, finding review, and report links.
- **Backend:** Python and FastAPI. It validates target registration, checks service connectivity, imports ZAP JSON, applies scope filters, stores assessor decisions, and generates HTML reports.
- **Database:** PostgreSQL through SQLAlchemy. Target authorization, scan metadata, raw scanner output, normalized findings, and assessor decisions are stored as separate records.
- **Scanner service:** OWASP ZAP runs in a separate Docker container. The current application checks whether its API responds but does not issue scan commands.
- **Deployment:** Docker Compose binds the frontend and backend to localhost. PostgreSQL and ZAP remain on the private Compose network.

## 8. Scope and Limitations

### In scope

- The authorized Contnental Fitness Gym web application and only the URLs explicitly approved for assessment.
- ZAP report import, scope-filtered observations, human review, and HTML reporting.
- Assessment of authentication, authorization, session handling, data in transit, and relevant application security configuration through approved manual procedures.
- Synthetic accounts and dummy records, when supplied and approved by the application owner.

### Out of scope

- Vercel edge infrastructure, Supabase Cloud infrastructure, third-party services, public websites, university networks, and any system not explicitly authorized.
- Port scans of Vercel or Supabase infrastructure.
- Denial-of-service, destructive testing, credential theft, or uncontrolled exploitation.

The current software does not execute reconnaissance, spidering, passive or active scanning, Nmap checks, or independent vulnerability validation. It does not authenticate users. It should only be run locally and is not ready for multi-user or production deployment. Its HTML report reflects uploaded observations and assessor decisions only.

## 9. Research Methodology

The assessment follows a planned sequence adapted from NIST SP 800-115 and the OWASP Web Security Testing Guide:

1. Obtain written authorization and define the approved target origin and URL paths.
2. Record the target, owner contact, in-scope URLs, and exclusions.
3. Run approved testing with suitable tools outside this workbench.
4. Import ZAP JSON and review scanner observations.
5. Perform manual technical validation using approved accounts and methods.
6. Record an assessor decision and severity for each finding.
7. Generate a report that explains evidence, limitations, and remediation.

The current implementation supports steps 2, a limited form of step 4, recording the assessor decision in step 6, and HTML report generation in step 7. It does not claim to complete the full methodology.

## 10. Security Assessment Workflow

The implemented workflow begins with target registration. The assessor confirms permission and provides scope. The backend validates the target URL and checks that in-scope URLs use the same scheme, host, and port. It blocks localhost, private or reserved IP addresses, and DNS results that include non-public addresses.

An assessor may then upload a ZAP JSON report. The import has a 10 MB file limit and a 1,000-alert limit. Finding instances are retained only when their origin and normalized URL path match the registered scope and do not match an exclusion. The raw JSON report is stored separately from normalized finding records. Imported observations begin as **Needs Review**.

The assessor reviews available descriptions, evidence, and remediation text, then selects **Confirmed**, **Rejected**, or **Needs Review**. Confirmed findings require an assessor severity. Only confirmed findings are counted in the report.

These controls apply to report import and registration. They are not scan-time protections. DNS rebinding, redirect handling during crawling, and request limits must be implemented before the platform is allowed to start scans.

## 11. AI Integration

AI is a planned extension and is not called by the current application. A later version may use a backend model service to explain structured scanner observations in plain language and suggest remediation steps.

Before any external model call is enabled, the system must identify the model and version, redact credentials and personal information, let the assessor preview the cleaned input, log the call, and keep the generated explanation separate from scanner output and assessor decisions. AI text must not confirm a vulnerability or invent evidence.

## 12. Technical Validation

Scanner alerts require evidence review. Planned validation may include checking response headers, TLS behavior, cookie attributes, access control with approved synthetic accounts, and request/response behavior. Each validation must record its method, result, and supporting evidence.

The current version does not issue validation requests. An imported alert remains a scanner observation until an assessor decides its status. This distinction prevents imported tool output from being presented as a verified finding.

## 13. Ethical Considerations

Assessment must be limited to systems for which written permission is available. The project will use synthetic accounts and dummy data, avoid destructive techniques, respect out-of-scope boundaries, and preserve enough evidence for review without exposing secrets.

The authorization confirmation in the current interface is a record entered by the assessor; it does not independently verify a signed authorization document. The platform is locally bound and has no login system, so it must not be exposed to a shared or public network.

## 14. Technologies Used

| Component | Technology | Current role |
|---|---|---|
| Frontend | Next.js, React, TypeScript | Target, findings, scan-import, and report interface |
| Backend | Python, FastAPI | Validation, JSON import, decisions, and HTML report |
| Database | PostgreSQL, SQLAlchemy | Persistent target and assessment data |
| Scanner | OWASP ZAP | Separate service; JSON report is imported manually |
| Containers | Docker Compose | Local frontend, backend, database, and ZAP services |
| Classification references | OWASP Top 10, WSTG, CWE, CVSS | Guidance for future finding classification; no scores are invented |

## 15. Expected Output

The current output is a locally hosted workbench that can store authorized target records, import and scope-filter ZAP JSON, record assessor decisions, and download an HTML report limited to confirmed findings. The report identifies that this version did not initiate a scan or perform AI analysis or independent validation.

The intended later output is a controlled end-to-end assessment workflow with approved scanner execution, technical validation evidence, optional redacted AI explanations, and PDF or Word reports. Those capabilities are not represented as complete in this repository.

## 16. Project Timeline

| Phase | Expected output | Status |
|---|---|---|
| Foundation | New project, retained visual language, service health checks | Implemented; frontend build and Compose configuration checked |
| Target and data workflow | Authorization record, scope validation, PostgreSQL persistence | Implemented; unit-tested |
| Evidence review | ZAP JSON import, scope filtering, assessor decisions | Implemented; unit-tested with synthetic JSON |
| Report generation | HTML report with confirmed findings and limitations | Implemented; unit-tested |
| Scanner execution and local training target | Controlled ZAP spider/passive scan against an authorized local application | Not implemented or tested |
| AI and redaction | Safe model integration with preview and audit trail | Not implemented |
| Final deployment verification | Live Docker service checks and complete workflow | Not completed; Docker engine was unavailable during this work |

## 17. References

- FIRST. (2023, updated 2024). *Common Vulnerability Scoring System version 4.0: Specification Document*. https://www.first.org/cvss/v4.0/specification-document
- MITRE. (n.d.). *Common Weakness Enumeration (CWE)*. https://cwe.mitre.org/
- National Institute of Standards and Technology. (2008). *Technical Guide to Information Security Testing and Assessment* (NIST SP 800-115). https://doi.org/10.6028/NIST.SP.800-115
- OWASP Foundation. (2025). *OWASP Top 10:2025*. https://top10.owasp.org/
- OWASP Foundation. (2025). *Web Security Testing Guide, version 4.2*. https://owasp.org/www-project-web-security-testing-guide/
- OWASP ZAP. (n.d.). *ZAP API Documentation*. https://www.zaproxy.org/docs/api/
