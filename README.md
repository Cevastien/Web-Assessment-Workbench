# Web Assessment Workbench

An evidence-first workspace for authorized web application assessments. The interface retains the source project's black sidebar, orange accent, warm gray canvas, restrained cards, and sans-serif typography.

## Start locally

1. Start Docker Desktop.
2. Copy `.env.example` to `.env`.
3. Run `docker compose up --build` from this directory. On first launch, Docker downloads the local Qwen model (about 2.5 GB); the AI status changes to connected when it is ready.
4. Open `http://localhost:3000`.

The local stack includes the frontend, FastAPI backend, PostgreSQL, OWASP ZAP, a private OWASP Juice Shop training target, and local Qwen inference through Ollama. Juice Shop is available to your browser at `http://localhost:3001`; from the scanner it is reachable only as `http://juice-shop:3000` on the private Compose network. Qwen runs on your computer and does not require a Hugging Face API token or send finding data to a hosted model provider.

## Register a target

Choose **Register target** and enter:

- **Target name**: a short label, such as `Local training app`.
- **Application description**: what the app does and any assessment boundaries.
- **Website URL**: for the included lab, `http://juice-shop:3000/`.
- **Owner or authorized contact**: a name or team contact. For the included lab, `Local training environment` is suitable.
- **In-scope URLs**: one per line. For the included lab, `http://juice-shop:3000/`.
- **Out-of-scope URLs**: paths the scan must skip, one per line. Leave blank for the isolated lab unless you have a reason to exclude paths.
- **Authorization confirmation**: required before saving a target.

The form opens prefilled for `https://contnental-gym.vercel.app/`. The owner contact is prefilled from the earlier registration. Login and registration paths are excluded from the initial public-site scope. Review these values and only check the authorization box if you have permission. Saving a target does not start a scan.

The training hostname is allowed only by the local Compose configuration; arbitrary local or private network URLs remain blocked. Public websites must resolve to public addresses and stay within the registered host and path scope.

## Scans and findings

Choose **Scans → Start passive scan** after registering an authorized target. The target page includes a site path directory that lists discovered pages, ZAP observations, Qwen explanations, and human review status. The scanner uses a ZAP context built from the registered in-scope and out-of-scope URLs, discovers pages with a shallow spider, and runs passive checks. Optional active checks require a separate authorization checkbox, are scope-constrained, and have strict time limits. Findings are saved separately from assessor decisions and begin as **Needs Review**. ZAP JSON reports can also be imported; out-of-scope observations are excluded.

A passive scan makes normal HTTP requests to the listed target. Only enter systems and URLs you are authorized to assess. The scanner backend is bound to localhost; do not expose it publicly.

## Backend API

The FastAPI service exposes interactive documentation at `http://localhost:8000/docs`. Compatibility routes are available for the assessment workflow:

- `POST /api/scans/import` accepts multipart fields `target_id` and `file` (a standard ZAP JSON report). The target must already be registered. Findings outside its allowed scope are skipped.
- `POST /api/findings/{finding_id}/analyze` asks the configured Qwen service for an explanation and remediation. Analysis is saved separately from scanner evidence.
- `POST /api/findings/{finding_id}/verify` accepts `{"action":"Confirm"}` or `{"action":"Reject"}` and an optional `severity_override` (`High`, `Medium`, `Low`, or `Info`).
- `GET /api/health` reports database and AI readiness as well as the dashboard's detailed service statuses.
- `GET /api/reports/generate?scan_id=...` downloads the HTML report for a scan; without `scan_id`, it uses the latest scan.

The `findings` table keeps the report fields (`target_url`, `vuln_name`, `risk_level`, `raw_description`, `evidence_url`, AI explanation/remediation, review status, and severity override) alongside scan linkage and assessor notes. Scanner descriptions, evidence, report JSON, and URLs are sanitized for common credentials and email addresses before storage. Finding IDs remain UUIDs so the dashboard can link each item to its scan.

## Local Qwen explanations

The default model is `qwen3:4b-instruct-2507-q4_K_M`, the 2.5 GB local quantization of Qwen3-4B-Instruct-2507. It is downloaded on first startup and runs through the private Ollama container. No Hugging Face API token is needed and model requests stay on your computer. The first download needs an internet connection and about 2.5 GB of free disk space; local inference can be slower on CPU-only computers.

Choose **Ask Qwen to explain** on a finding to request a plain-language explanation, possible impact, a cautious severity suggestion, validation steps, and remediation. The backend redacts common secrets and email addresses before sending only scanner details and the affected URL path to the local model. The explanation is stored separately from ZAP evidence and does not confirm a vulnerability. Qwen explains scanner findings; it does not run scans or decide if a finding is real.

To use hosted Hugging Face inference instead, set `AI_PROVIDER=huggingface`, `HF_MODEL=Qwen/Qwen3-4B-Instruct-2507:nscale`, and add an access token with the Inference Providers permission to `.env`. Hosted inference may incur charges; check your Hugging Face billing before using it. Keep the token server-side and never commit `.env`.

## Implemented and unavailable items

Implemented: target authorization and scope registration, public URL checks, local training target, live service health checks, scope-filtered ZAP JSON import, a report-backed finding path directory, Qwen explanations, human review decisions, and HTML reports. The hosted dashboard uses uploaded reports; it does not require a hosted ZAP scanner.

Not implemented: Nmap port scans, authenticated target sessions, independent automated validation, PDF/Word report export, multi-user login, and a deployed live-scanner service. The Vercel dashboard is connected to the Render API for report import, AI explanations, review decisions, and reports. Live scanning is not offered in the hosted dashboard; import a ZAP JSON report created for the selected authorized target.
