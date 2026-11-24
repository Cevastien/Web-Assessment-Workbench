# Web Assessment Workbench

An evidence-first workspace for authorized web application assessments. The interface retains the source project's black sidebar, orange accent, warm gray canvas, restrained cards, and sans-serif typography.

## Current implementation

- Next.js and React frontend with target registration, explicit authorization and scope fields, and service health indicators.
- FastAPI backend with live API/database/ZAP checks and server-side URL validation that rejects credentials, non-HTTP schemes, localhost, private/reserved IPs, and hostnames resolving to private/reserved addresses.
- PostgreSQL persistence for authorized targets, imported scan records, raw ZAP output, and separated finding observations and assessor decisions.
- ZAP JSON import with a 10 MB file limit, a 1,000-alert limit, origin/path scope filtering, and all findings set to Needs Review.
- Assessor verification and severity, plus HTML report download that includes only confirmed findings and states the current method limitations.
- Docker Compose definitions for the frontend, backend, PostgreSQL, and OWASP ZAP.
- Integrations report their observed state; configuration alone is never presented as connectivity.

The application does not launch ZAP scans, run Nmap, perform independent technical validation, or call an AI service. Authentication, secret redaction, PDF/Word reports, and the local end-to-end training target are also not implemented. Those functions are explicitly shown as unavailable; imported scanner observations are not presented as verified vulnerabilities.

Run target validation checks from `backend/` with `python -m unittest discover -s tests -v`.

## Start

Copy `.env.example` to `.env`, then run `docker compose up --build`. The services bind to localhost: the frontend is at `http://localhost:3000` and the API health endpoint is at `http://localhost:8000/health`.

## Safety

This version only imports reports produced outside the platform. It never launches a scan. Do not use it as an authenticated, multi-user service: login, audit logging, encrypted evidence handling, scan-time DNS pinning/revalidation, redirect scope enforcement, and active-scan controls remain future work. Keep the Compose stack bound to localhost.
