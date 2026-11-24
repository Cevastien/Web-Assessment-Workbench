# Technical assessment and phased plan

## Source repository inspected read-only

Reference: `https://github.com/Cevastien/SQL-Injection-Detection`

The checked-out source is a hybrid application:

- Frontend: Next.js 16, React 19, TypeScript, Tailwind CSS, and Tabler icons.
- Backend: Python FastAPI with scikit-learn/XGBoost model loading and HTTP endpoints.
- Current data flow: SQL query analysis, model management, explainability, model performance, and browser-local detection history.
- Current persistence: model artifacts are runtime uploads; detection history is stored in browser local storage.
- No PostgreSQL integration or user authentication was found in the source files inspected.

The SQL query classifier and its model artifacts are purpose-built for SQL injection text classification. They are not a web application scanner and are excluded from this project. The visual identity is retained: near-black sidebar, orange primary action, warm gray canvas, light cards with subtle borders, restrained spacing, and sans-serif type.

## Proposal context

The supplied Deliverable 1 describes the Contnental Fitness Gym Management System, a Next.js/React and Supabase application. It proposes FastAPI, PostgreSQL, OWASP ZAP, and Claude API, with synthetic accounts, manual evidence review, and reports. It explicitly excludes port-scanning Vercel and Supabase infrastructure. The authorization appendix and synthetic assessment accounts were described in the proposal but were not available for independent verification here.

## New project architecture

```text
ai-web-vulnerability-assessment/
├── frontend/                 Next.js app, accessible dashboard and assessment views
├── backend/                  FastAPI, PostgreSQL records, URL/scope validation, ZAP JSON import
├── infra/                    Reserved for scanner isolation and local test target
├── docs/                     Technical assessment, methodology, and operator guidance
├── docker-compose.yml        Frontend, API, PostgreSQL, and OWASP ZAP services
└── README.md
```

The implementation remains independent of the source repository. It validates and persists authorized public targets, checks service health, imports OWASP ZAP JSON observations with scope filtering, records assessor verification, and exports an HTML report. Scanner execution, AI interpretation, and independent technical validation remain unavailable.

## Phases

1. **Foundation and truthful service status:** complete for the frontend build and Compose configuration.
2. **Target registration and authorization:** URL checks, explicit confirmation, scope matching, and PostgreSQL persistence are implemented. Authentication, audit history, scan-time DNS/rebinding/redirect controls remain.
3. **Safe reconnaissance and scanner integration:** ZAP JSON import is implemented with size, alert-count, origin, and path scope checks. In-platform spider/passive/active scan execution and Nmap are not implemented; never scan Vercel/Supabase infrastructure.
4. **Finding workflow:** raw ZAP output, normalized scanner observations, and assessor decisions are stored separately. Confirm/reject/needs-review and assessor severity are implemented. AI analysis, redaction preview, and technical validation are not implemented.
5. **Reports and revised proposal:** HTML report export includes confirmed findings and explicit limitations. PDF/Word export and full proposal rewrite remain.
6. **End-to-end verification:** unit checks cover target authorization and scope rules. Docker services were configuration-checked but not started; no local vulnerable target or complete scan workflow has been exercised.

## Current boundary

Implemented: frontend dashboard, target authorization form, PostgreSQL persistence, live API/database/ZAP health checks, ZAP JSON import and scope filtering, assessor verification, HTML report export, Compose definitions.

Not yet implemented: authentication, scan execution, crawl/endpoint storage, independent technical validation, AI, redaction controls, PDF/Word report, Nmap, revised academic proposal, and end-to-end local vulnerable-target workflow. No scanner result or AI result is synthesized.
