"use client";

import { useEffect, useRef, useState } from "react";
import {
  IconActivity,
  IconAlertTriangle,
  IconArrowLeft,
  IconBrain,
  IconChevronRight,
  IconCircleCheck,
  IconDatabase,
  IconFileText,
  IconFilter,
  IconGlobe,
  IconLayoutDashboard,
  IconListDetails,
  IconLock,
  IconMenu2,
  IconPlus,
  IconRadar,
  IconRefresh,
  IconSearch,
  IconSettings,
  IconUpload,
  IconX,
} from "@tabler/icons-react";

const API = "/backend";
const DEMO_MODE = process.env.NEXT_PUBLIC_DEMO_MODE === "true";
const DEMO_STORAGE_KEY = "web-assessment-workbench-demo-v1";

const nav = [
  { label: "Dashboard", icon: IconLayoutDashboard },
  { label: "Assessments", icon: IconListDetails },
  { label: "Vulnerability Findings", icon: IconAlertTriangle },
  { label: "Reports", icon: IconFileText },
];

type Service = { status: string; detail: string };
type Health = { services: Record<string, Service> };
type RegisteredTarget = {
  id: string;
  name: string;
  url: string;
  application_description: string;
  owner_contact: string;
  in_scope: string[];
  out_of_scope: string[];
};
type Finding = {
  id: string;
  scan_id: string;
  title: string;
  url: string;
  category: string;
  scanner_severity: string;
  description: string;
  remediation: string;
  evidence: string;
  classification: Record<string, unknown>;
  verification: string;
  assessor_severity: string | null;
  assessor_comment: string;
  ai_analysis?: {
    provider: string;
    model: string;
    analyzed_at: string;
    result: {
      explanation: string;
      why_it_matters: string;
      possible_impact: string;
      suggested_severity: string;
      reasoning: string;
      validation_steps: string[];
      remediation: string;
      cwe: string | null;
      owasp_category: string | null;
      evidence_assessment?: string;
      evidence_reasoning?: string;
      affected_parameters?: string[];
      investigation_steps?: AiActionStep[];
      fix_steps?: AiActionStep[];
      verification_steps?: AiActionStep[];
      requires_active_test?: boolean;
      active_test_note?: string;
    };
    notice: string;
  } | null;
};
type AiActionStep = {
  tool: string;
  where: string;
  steps: string[];
  expected_result: string;
  example?: string;
};
type Scan = {
  id: string;
  target_id: string;
  source: string;
  status: string;
  created_at: string;
  findings_count: number;
  discovered_endpoints: string[];
  configuration?: Record<string, unknown>;
};
type DemoState = { targets: RegisteredTarget[]; findings: Finding[]; scans: Scan[] };
type AssessmentStatus = "Processing" | "Needs Review" | "Completed" | "Failed";

function loadDemoState(): DemoState {
  try {
    const value = localStorage.getItem(DEMO_STORAGE_KEY);
    if (value) return JSON.parse(value) as DemoState;
  } catch {
    // Use an empty workspace when browser storage is unavailable or malformed.
  }
  return { targets: [], findings: [], scans: [] };
}

function saveDemoState(next: Partial<DemoState>) {
  const current = loadDemoState();
  localStorage.setItem(DEMO_STORAGE_KEY, JSON.stringify({ ...current, ...next }));
}

function endpointPath(value: string) {
  try {
    return new URL(value).pathname.replace(/\/+$/, "") || "/";
  } catch {
    return value;
  }
}

function plainText(value: string) {
  return value
    .replace(/<[^>]*>/g, " ")
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi, "'")
    .replace(/\s+/g, " ")
    .trim();
}

async function readApiJson(response: Response) {
  if (!response.headers.get("content-type")?.includes("application/json")) {
    throw new Error("The backend is not connected to this preview yet.");
  }
  return response.json();
}

function severityRank(value: string) {
  return value.toLowerCase() === "critical" || value.toLowerCase() === "high";
}

export default function Home() {
  const [section, setSection] = useState("Dashboard");
  const [health, setHealth] = useState<Health | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [formMode, setFormMode] = useState<"target" | "assessment">("target");
  const [assessmentTargetId, setAssessmentTargetId] = useState("new");
  const [assessmentFile, setAssessmentFile] = useState<File | null>(null);
  const [processingScanId, setProcessingScanId] = useState("");
  const [processingTargetName, setProcessingTargetName] = useState("");
  const [processingFindingCount, setProcessingFindingCount] = useState(0);
  const [processingPhase, setProcessingPhase] = useState<"upload" | "analysis" | "complete">("upload");
  const [processingDataReady, setProcessingDataReady] = useState(false);
  const [processingStartedAt, setProcessingStartedAt] = useState(0);
  const [mobileNav, setMobileNav] = useState(false);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState("");
  const [noticeError, setNoticeError] = useState(false);
  const [registered, setRegistered] = useState<RegisteredTarget | null>(null);
  const [targets, setTargets] = useState<RegisteredTarget[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [findingPathFilter, setFindingPathFilter] = useState("");
  const [findingScanFilter, setFindingScanFilter] = useState("");
  const [findingSearch, setFindingSearch] = useState("");
  const [findingSeverityFilter, setFindingSeverityFilter] = useState("All severities");
  const [findingReviewFilter, setFindingReviewFilter] = useState("All review states");
  const [assessmentSearch, setAssessmentSearch] = useState("");
  const [assessmentFilter, setAssessmentFilter] = useState("All");
  const [settingsView, setSettingsView] = useState("Target & scope");
  const [selectedFindingId, setSelectedFindingId] = useState("");
  const [deleteAuditTarget, setDeleteAuditTarget] = useState<Scan | null>(null);
  const [aiRunningIds, setAiRunningIds] = useState<string[]>([]);
  const [aiError, setAiError] = useState("");
  const [target, setTarget] = useState({
    name: "",
    url: "",
    application_description: "",
    owner_contact: "",
    authorized: false,
    in_scope: "",
    out_of_scope: "",
  });
  const attemptedAiIds = useRef(new Set<string>());

  async function refreshHealth() {
    if (DEMO_MODE) {
      setHealth({
        services: {
          api: { status: "disconnected", detail: "Browser-only preview" },
          database: { status: "disconnected", detail: "Backend not connected" },
          zap: { status: "disconnected", detail: "Not available in preview" },
          ai: { status: "disconnected", detail: "Not configured" },
        },
      });
      return;
    }
    try {
      const response = await fetch(`${API}/health`);
      setHealth(await readApiJson(response));
    } catch {
      setHealth({
        services: {
          api: { status: "disconnected", detail: "API unavailable" },
          database: { status: "disconnected", detail: "Could not check service" },
          zap: { status: "disconnected", detail: "Could not check service" },
          ai: { status: "disconnected", detail: "Not configured" },
        },
      });
    }
  }

  async function loadWorkspace() {
    if (DEMO_MODE) {
      const state = loadDemoState();
      setTargets(state.targets);
      setRegistered(state.targets[0] ?? null);
      setFindings(state.findings);
      setScans(state.scans);
      return;
    }
    const [targetResponse, scanResponse, findingResponse] = await Promise.all([
      fetch(`${API}/targets`),
      fetch(`${API}/scans`),
      fetch(`${API}/findings`),
    ]);
    const [targetRows, scanRows, findingRows] = await Promise.all([
      targetResponse.ok ? readApiJson(targetResponse) : [],
      scanResponse.ok ? readApiJson(scanResponse) : [],
      findingResponse.ok ? readApiJson(findingResponse) : [],
    ]);
    setTargets(targetRows as RegisteredTarget[]);
    setRegistered((current) =>
      current ? (targetRows as RegisteredTarget[]).find((row) => row.id === current.id) ?? current : (targetRows as RegisteredTarget[])[0] ?? null,
    );
    setScans(scanRows as Scan[]);
    setFindings(findingRows as Finding[]);
  }

  useEffect(() => {
    void refreshHealth();
    const timer = setInterval(() => void refreshHealth(), 15000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    void loadWorkspace().catch(() => {
      setNoticeError(true);
      setNotice("Could not load assessments from the API. Refresh to try again.");
    });
  }, []);

  useEffect(() => {
    if (DEMO_MODE || !scans.some((scan) => scan.status === "running")) return;
    const timer = setInterval(() => {
      void Promise.all([fetch(`${API}/scans`), fetch(`${API}/findings`)]).then(async ([scanResponse, findingResponse]) => {
        if (scanResponse.ok) setScans((await readApiJson(scanResponse)) as Scan[]);
        if (findingResponse.ok) setFindings((await readApiJson(findingResponse)) as Finding[]);
      }).catch(() => undefined);
    }, 3000);
    return () => clearInterval(timer);
  }, [scans]);

  useEffect(() => {
    if (DEMO_MODE) return;
    const pending = findings.filter((item) => !item.ai_analysis && !attemptedAiIds.current.has(item.id));
    if (!pending.length) return;
    pending.forEach((item) => attemptedAiIds.current.add(item.id));
    setAiError("");
    void (async () => {
      let analyzed = 0;
      let failure = "";
      for (const item of pending) {
        setAiRunningIds((ids) => [...ids, item.id]);
        try {
          const response = await fetch(`${API}/findings/${item.id}/analyze`, { method: "POST" });
          const result = await readApiJson(response);
          if (!response.ok) throw new Error(result.detail || "Automatic AI analysis failed");
          setFindings((rows) => rows.map((row) => row.id === item.id ? result as Finding : row));
          analyzed++;
        } catch (error) {
          failure = error instanceof Error ? error.message : "Automatic AI analysis failed";
          setAiError(failure);
          setNoticeError(true);
          setNotice(`Automatic AI analysis stopped: ${failure}`);
          break;
        } finally {
          setAiRunningIds((ids) => ids.filter((id) => id !== item.id));
        }
      }
      if (analyzed > 0 && !failure) {
        setNoticeError(false);
        setNotice(`AI analyzed ${analyzed} finding${analyzed === 1 ? "" : "s"}. Review evidence before confirming.`);
      }
    })();
  }, [findings]);

  useEffect(() => {
    if (!processingScanId || !processingDataReady || !scans.some((scan) => scan.id === processingScanId)) return;
    const scanFindings = findings.filter((finding) => finding.scan_id === processingScanId);
    const analysisFinished = scanFindings.length === 0 || scanFindings.every((finding) => Boolean(finding.ai_analysis)) || Boolean(aiError);
    if (!analysisFinished) return;
    setProcessingPhase("complete");
    const timer = setTimeout(() => {
      setFindingPathFilter("");
      setFindingScanFilter(processingScanId);
      setSelectedFindingId("");
      setSection("Vulnerability Findings");
      setProcessingScanId("");
      setProcessingDataReady(false);
    }, Math.max(1300 - (Date.now() - processingStartedAt), 0));
    return () => clearTimeout(timer);
  }, [processingScanId, processingDataReady, processingStartedAt, scans, findings, aiError]);

  function openRegisterForm() {
    setFormMode("target");
    setTarget({
      name: "Contnental Fitness Gym",
      url: "https://contnental-gym.vercel.app/",
      application_description: "Fitness and strength-conditioning gym website in Davao City.",
      owner_contact: "Earl",
      authorized: false,
      in_scope: "https://contnental-gym.vercel.app/",
      out_of_scope: "https://contnental-gym.vercel.app/login\nhttps://contnental-gym.vercel.app/register",
    });
    setNotice("");
    setSection("Settings");
    setSettingsView("Target & scope");
    setShowForm(true);
  }

  function startNewAssessment() {
    setNotice("");
    setNoticeError(false);
    setAiError("");
    const currentTarget = registered ?? targets[0];
    if (currentTarget) {
      setAssessmentTargetId(currentTarget.id);
      setTarget({
        name: currentTarget.name,
        url: currentTarget.url,
        application_description: currentTarget.application_description,
        owner_contact: currentTarget.owner_contact,
        authorized: true,
        in_scope: currentTarget.in_scope.join("\n"),
        out_of_scope: currentTarget.out_of_scope.join("\n"),
      });
    } else {
      setAssessmentTargetId("new");
      setTarget({
        name: "Contnental Fitness Gym",
        url: "https://contnental-gym.vercel.app/",
        application_description: "Fitness and strength-conditioning gym website in Davao City.",
        owner_contact: "Earl",
        authorized: false,
        in_scope: "https://contnental-gym.vercel.app/",
        out_of_scope: "https://contnental-gym.vercel.app/login\nhttps://contnental-gym.vercel.app/register",
      });
    }
    setAssessmentFile(null);
    setFormMode("assessment");
    setShowForm(true);
  }

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setNotice("");
    try {
      if (DEMO_MODE) {
        const parsed = new URL(target.url);
        if (!["http:", "https:"].includes(parsed.protocol)) throw new Error("Enter a complete HTTP or HTTPS website URL.");
        const normalized: RegisteredTarget = {
          id: `demo-${Date.now()}`,
          name: parsed.hostname,
          url: parsed.href,
          application_description: "",
          owner_contact: "",
          in_scope: [parsed.href],
          out_of_scope: [],
        };
        const rows = [normalized, ...targets.filter((row) => row.url !== normalized.url)];
        saveDemoState({ targets: rows });
        setRegistered(normalized);
        setTargets(rows);
        setNotice("Saved in this browser only. The preview did not contact the site or start a scan.");
        setShowForm(false);
        return;
      }
      const response = await fetch(`${API}/targets/validate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ...target,
          in_scope: target.in_scope.split("\n").map((item) => item.trim()).filter(Boolean),
          out_of_scope: target.out_of_scope.split("\n").map((item) => item.trim()).filter(Boolean),
        }),
      });
      const data = await readApiJson(response);
      if (!response.ok) throw new Error(data.detail || "Could not validate target");
      const savedTarget = data.target as RegisteredTarget;
      setRegistered(savedTarget);
      setTargets((rows) => [savedTarget, ...rows.filter((row) => row.id !== savedTarget.id)]);
      setNotice(data.message as string);
      setShowForm(false);
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Unable to reach API");
      setNoticeError(true);
    } finally {
      setBusy(false);
    }
  }

  async function submitAssessment(event: React.FormEvent) {
    event.preventDefault();
    if (!assessmentFile) {
      setNotice("Choose a ZAP JSON report to import.");
      setNoticeError(true);
      return;
    }
    setBusy(true);
    setNotice("");
    setNoticeError(false);
    setProcessingPhase("upload");
    setProcessingDataReady(false);
    setProcessingFindingCount(0);
    setProcessingStartedAt(Date.now());
    setProcessingTargetName(selectedAssessmentTarget?.name ?? target.name);
    const returnSection = section;
    setSection("Assessment Progress");
    setShowForm(false);
    try {
      let assessmentTarget = targets.find((row) => row.id === assessmentTargetId)
        ?? (registered?.id === assessmentTargetId ? registered : null);
      if (assessmentTargetId === "new") {
        if (DEMO_MODE) {
          throw new Error("The preview can save a target locally, but report import needs the connected API.");
        }
        const targetResponse = await fetch(`${API}/targets/validate`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            ...target,
            in_scope: target.in_scope.split("\n").map((item) => item.trim()).filter(Boolean),
            out_of_scope: target.out_of_scope.split("\n").map((item) => item.trim()).filter(Boolean),
          }),
        });
        const targetResult = await readApiJson(targetResponse);
        if (!targetResponse.ok) throw new Error(targetResult.detail || "Could not validate target");
        assessmentTarget = targetResult.target as RegisteredTarget;
        setRegistered(assessmentTarget);
        setTargets((rows) => [assessmentTarget!, ...rows.filter((row) => row.id !== assessmentTarget!.id)]);
        setAssessmentTargetId(assessmentTarget.id);
      }
      if (!assessmentTarget) throw new Error("Choose or register a target before importing the report.");

      const form = new FormData();
      form.append("file", assessmentFile);
      const response = await fetch(`${API}/targets/${assessmentTarget.id}/scans/import-zap`, { method: "POST", body: form });
      const result = await readApiJson(response);
      if (!response.ok) throw new Error(result.detail || "Report import failed");
      const scanId = String(result.scan_id || "");
      const importedCount = Number(result.findings_imported || 0);
      setProcessingScanId(scanId);
      setProcessingFindingCount(importedCount);
      setProcessingTargetName(assessmentTarget.name);
      setProcessingPhase(importedCount > 0 ? "analysis" : "complete");
      setNotice("");
      setNoticeError(false);
      setShowForm(false);
      await loadWorkspace();
      setProcessingDataReady(true);
    } catch (error) {
      setSection(returnSection);
      setShowForm(true);
      setNotice(error instanceof TypeError ? "Could not reach the assessment API. Check the connection and retry." : error instanceof Error ? error.message : "Could not import the ZAP report.");
      setNoticeError(true);
    } finally {
      setBusy(false);
    }
  }

  async function importZap(event: React.ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (!file || !registered) return;
    setBusy(true);
    setNotice("");
    setNoticeError(false);
    try {
      const form = new FormData();
      form.append("file", file);
      const response = await fetch(`${API}/targets/${registered.id}/scans/import-zap`, { method: "POST", body: form });
      let data: Record<string, unknown>;
      try {
        data = await response.json();
      } catch {
        throw new Error("The API returned an unreadable response. Check the hosted API status and try again.");
      }
      if (!response.ok) throw new Error(String(data.detail || "Report import failed"));
      setNotice(`Imported ${data.findings_imported} scanner observations. ${data.instances_skipped_outside_scope} out-of-scope instances were skipped.`);
      await loadWorkspace();
    } catch (error) {
      setNotice(error instanceof TypeError ? "Could not reach the hosted API. It may be waking up; wait briefly and retry." : error instanceof Error ? error.message : "Could not import the ZAP report");
      setNoticeError(true);
    } finally {
      setBusy(false);
      event.target.value = "";
    }
  }

  async function decideFinding(item: Finding, verification: "confirmed" | "rejected" | "needs_review") {
    try {
      const response = await fetch(`${API}/findings/${item.id}/verification`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ verification, comment: item.assessor_comment || "" }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Could not save decision");
      setFindings((rows) => rows.map((row) => row.id === item.id ? data as Finding : row));
      setNoticeError(false);
      setNotice(`Finding marked ${verification.replace("_", " ")}. This decision is saved to the audit.`);
    } catch (error) {
      setNoticeError(true);
      setNotice(error instanceof Error ? error.message : "Could not save decision");
    }
  }

  async function retryQwenAnalysis(item: Finding) {
    setAiError("");
    setNotice("");
    setNoticeError(false);
    setAiRunningIds((ids) => ids.includes(item.id) ? ids : [...ids, item.id]);
    try {
      const response = await fetch(`${API}/findings/${item.id}/analyze`, { method: "POST" });
      const data = await readApiJson(response);
      if (!response.ok) throw new Error(data.detail || "Qwen analysis failed");
      setFindings((rows) => rows.map((row) => row.id === item.id ? data as Finding : row));
      setNotice("Qwen analysis is ready. Check the evidence and suggested fix before confirming the finding.");
    } catch (error) {
      const message = error instanceof TypeError ? "Could not reach the AI service. Check the backend connection and retry." : error instanceof Error ? error.message : "Qwen analysis failed.";
      setAiError(message);
      setNotice(message);
      setNoticeError(true);
    } finally {
      setAiRunningIds((ids) => ids.filter((id) => id !== item.id));
    }
  }

  async function clearAudit(scan: Scan) {
    setBusy(true);
    setNotice("");
    setNoticeError(false);
    try {
      if (DEMO_MODE) {
        const nextScans = scans.filter((row) => row.id !== scan.id);
        const nextFindings = findings.filter((row) => row.scan_id !== scan.id);
        setScans(nextScans);
        setFindings(nextFindings);
        saveDemoState({ scans: nextScans, findings: nextFindings });
        setDeleteAuditTarget(null);
        setNotice(`Audit cleared. Removed ${findings.length - nextFindings.length} findings and their review decisions.`);
        return;
      }
      const response = await fetch(`${API}/scans/${scan.id}`, { method: "DELETE" });
      const result = await readApiJson(response);
      if (!response.ok) throw new Error(result.detail || "Could not clear this audit");
      setScans((rows) => rows.filter((row) => row.id !== scan.id));
      setFindings((rows) => rows.filter((row) => row.scan_id !== scan.id));
      setDeleteAuditTarget(null);
      setNotice(`Audit cleared. Removed ${result.findings_deleted} findings and their review decisions.`);
    } catch (error) {
      setNoticeError(true);
      setNotice(error instanceof Error ? error.message : "Could not clear the selected audit");
    } finally {
      setBusy(false);
    }
  }

  const targetFor = (scan: Scan) => targets.find((item) => item.id === scan.target_id);
  const findingsFor = (scanId: string) => findings.filter((item) => item.scan_id === scanId);
  const statsFor = (scan: Scan) => {
    const rows = findingsFor(scan.id);
    const needsReview = rows.filter((item) => item.verification === "needs_review").length;
    const analyzed = rows.filter((item) => Boolean(item.ai_analysis)).length;
    const criticalHigh = rows.filter((item) => severityRank(item.ai_analysis?.result.suggested_severity ?? item.scanner_severity)).length;
    let status: AssessmentStatus;
    if (scan.status === "running") status = "Processing";
    else if (scan.status === "failed") status = "Failed";
    else if (needsReview > 0) status = "Needs Review";
    else status = "Completed";
    const aiStatus = rows.length === 0
      ? "No findings"
      : analyzed === rows.length
        ? "Complete"
        : analyzed > 0
          ? `${analyzed} / ${rows.length} analyzed`
          : aiError
            ? "Unavailable"
            : aiRunningIds.some((id) => rows.some((item) => item.id === id))
              ? "Analyzing"
              : "Pending";
    return { rows, needsReview, analyzed, criticalHigh, status, aiStatus };
  };

  const assessmentCounts = {
    all: scans.length,
    processing: scans.filter((scan) => statsFor(scan).status === "Processing").length,
    needsReview: scans.filter((scan) => statsFor(scan).status === "Needs Review").length,
    completed: scans.filter((scan) => statsFor(scan).status === "Completed").length,
    failed: scans.filter((scan) => statsFor(scan).status === "Failed").length,
  };
  const findingsToReview = findings.filter((item) => item.verification === "needs_review").length;
  const confirmedFindings = findings.filter((item) => item.verification === "confirmed").length;
  const filteredAssessments = scans.filter((scan) => {
    const stats = statsFor(scan);
    const query = assessmentSearch.trim().toLowerCase();
    const targetInfo = targetFor(scan);
    const searchable = `${targetInfo?.name ?? ""} ${targetInfo?.url ?? ""} ${scan.source}`.toLowerCase();
    return (assessmentFilter === "All" || stats.status === assessmentFilter) && (!query || searchable.includes(query));
  });

  const filteredFindings = findings.filter((item) => {
    const query = findingSearch.trim().toLowerCase();
    const searchable = `${item.title} ${item.category} ${item.url} ${item.description}`.toLowerCase();
    return (!findingPathFilter || endpointPath(item.url) === findingPathFilter)
      && (!findingScanFilter || item.scan_id === findingScanFilter)
      && (!query || searchable.includes(query))
      && (findingSeverityFilter === "All severities" || item.scanner_severity.toLowerCase() === findingSeverityFilter.toLowerCase())
      && (findingReviewFilter === "All review states" || item.verification === findingReviewFilter);
  });
  const selectedFinding = findings.find((item) => item.id === selectedFindingId);
  const selectedAssessmentTarget = targets.find((item) => item.id === assessmentTargetId)
    ?? (registered?.id === assessmentTargetId ? registered : null);
  const processingPercent = processingPhase === "upload" ? 35 : processingPhase === "analysis" ? 78 : 100;
  const processingAiRunning = aiRunningIds.some((id) => findings.some((item) => item.id === id && item.scan_id === processingScanId));
  const titles: Record<string, string> = {
    Dashboard: "Assessment dashboard",
    "New Assessment": "New assessment",
    "Assessment Progress": "Preparing your findings",
    Assessments: "Assessment history",
    "Vulnerability Findings": "Vulnerability findings",
    Reports: "Assessment reports",
    Settings: "Workspace settings",
  };
  const services = [
    { name: "API backend", key: "api", icon: IconActivity },
    { name: "PostgreSQL database", key: "database", icon: IconDatabase },
    { name: "OWASP ZAP · JSON import", key: "zap", icon: IconRadar },
    { name: "AI service", key: "ai", icon: IconBrain },
  ];

  function assessmentTable(rows: Scan[], compact = false) {
    if (rows.length === 0) {
      return (
        <section className="panel empty-state">
          <div className="empty-icon"><IconListDetails /></div>
          <h2>{scans.length ? "No assessments match these filters" : "No assessments yet"}</h2>
          <p>{scans.length ? "Clear the status filter or search another target." : "Upload an OWASP ZAP JSON report to create your first assessment record."}</p>
          {!scans.length && <button className="primary" onClick={startNewAssessment}><IconPlus size={16} /> New assessment</button>}
        </section>
      );
    }
    return (
      <div className="table-scroll">
        <table className="data-table assessment-table">
          <thead><tr><th>Target</th><th>Assessment date</th><th>Status</th><th>Findings</th>{!compact && <><th>Critical / high</th><th>AI analysis</th><th>Human review</th></>}<th>Actions</th></tr></thead>
          <tbody>{rows.map((scan) => {
            const info = targetFor(scan);
            const summary = statsFor(scan);
            return <tr key={scan.id}>
              <td><b>{info?.name ?? "Registered target"}</b><small>{info?.url ? new URL(info.url).hostname : scan.source}</small></td>
              <td>{new Date(scan.created_at).toLocaleDateString()}</td>
              <td><span className={`pill ${summary.status.toLowerCase().replaceAll(" ", "-")}`}><i />{summary.status}</span></td>
              <td>{scan.findings_count}</td>
              {!compact && <><td>{summary.criticalHigh}</td><td><span className={`ai-state ${summary.aiStatus === "Complete" ? "complete" : summary.aiStatus === "Unavailable" ? "unavailable" : ""}`}>{summary.aiStatus}</span></td><td>{summary.needsReview ? `${summary.needsReview} need review` : "Reviewed"}</td></>}
              <td><div className="row-actions"><button className="table-action" onClick={() => { setFindingScanFilter(scan.id); setFindingPathFilter(""); setSection("Vulnerability Findings"); }}>Review</button><a className="table-action" href={`${API}/reports/${scan.id}/pdf`} target="_blank" rel="noreferrer">Report</a></div></td>
            </tr>;
          })}</tbody>
        </table>
      </div>
    );
  }

  function renderFindingCard(item: Finding) {
    const ai = item.ai_analysis?.result;
    const actionSection = (title: string, steps?: AiActionStep[]) => steps?.length ? <section className="ai-action-section"><h3>{title}</h3><div className="ai-action-list">{steps.map((action, index) => <article className="ai-action-card" key={`${title}-${index}`}><div className="ai-action-heading"><b>{action.tool || "Manual review"}</b>{action.where && <span>{action.where}</span>}</div><ol>{(action.steps ?? []).map((step, stepIndex) => <li key={stepIndex}>{step}</li>)}</ol>{action.expected_result && <p><b>Expected result:</b> {action.expected_result}</p>}{action.example && <pre>{action.example}</pre>}</article>)}</div></section> : null;
    return <article className="panel finding-card" key={item.id}>
      <div className="finding-head"><div><span className="eyebrow">SCANNER OBSERVATION · {item.category}</span><h2>{item.title}</h2></div><span className={`decision ${item.verification}`}>{item.verification.replace("_", " ")}</span></div>
      <p className="finding-url">{item.url}</p>
      <div className="finding-meta"><span>Scanner’s original label: <b>{item.scanner_severity}</b></span></div>
      {item.ai_analysis ? <section className="panel ai-analysis"><div className="ai-analysis-title"><div><div className="eyebrow">QWEN REVIEW</div><h3>{ai?.suggested_severity ?? "Risk level unavailable"}</h3></div><span className={`evidence-rating ${ai?.evidence_assessment ?? "insufficient"}`}>{(ai?.evidence_assessment ?? "insufficient").replaceAll("_", " ")}</span></div><p>{ai?.explanation}</p><p><b>Why this could matter:</b> {ai?.why_it_matters}</p><p><b>What could happen:</b> {ai?.possible_impact}</p><p><b>Why Qwen chose this risk level:</b> {ai?.reasoning}</p><p><b>How strong the evidence is:</b> {ai?.evidence_reasoning}</p>{Boolean(ai?.affected_parameters?.length) && <p><b>Parts of the page involved:</b> {ai?.affected_parameters?.join(", ")}</p>}{actionSection("Check whether this is a real issue", ai?.investigation_steps)}{ai?.remediation && <p><b>Suggested fix:</b> {ai.remediation}</p>}{actionSection("Steps for the website developer", ai?.fix_steps)}{actionSection("Check that the fix worked", ai?.verification_steps)}{ai?.requires_active_test && <div className="active-test-note"><b>A hands-on security check may be needed:</b> {ai.active_test_note || "Only perform this check on the authorized website."}</div>}<small>AI-assisted review · {new Date(item.ai_analysis.analyzed_at).toLocaleString()}</small></section> : <section className="panel ai-analysis ai-missing"><div className="eyebrow">AI REVIEW NOT READY</div><p>{aiRunningIds.includes(item.id) ? "The assistant is reviewing this alert…" : "We couldn’t get an AI review yet. This alert has not been assessed, and no AI repair instructions are available. You can leave it for later; confirmation stays unavailable until the review is complete."}</p>{!aiRunningIds.includes(item.id) && !DEMO_MODE && <button className="secondary" onClick={() => void retryQwenAnalysis(item)}>Try AI review again</button>}{Boolean(aiError) && <details className="technical-details"><summary>Technical details</summary><p>{aiError}</p></details>}</section>}
      <details className="technical-details"><summary>Scanner evidence and technical details</summary><div className="evidence-section"><div className="eyebrow">ORIGINAL SCANNER DESCRIPTION</div><p className="finding-description">{plainText(item.description) || "No scanner description was supplied."}</p></div><section className="panel scanner-remediation"><div className="eyebrow">ORIGINAL SCANNER SUGGESTION</div><p>{plainText(item.remediation) || "The scanner did not include a suggested fix."}</p></section><p><b>Observed evidence:</b> {item.evidence || "No evidence supplied."}</p><pre>{JSON.stringify(item.classification, null, 2)}</pre></details>
      <label className="comment-label">Verification notes<textarea rows={2} value={item.assessor_comment} onChange={(event) => setFindings((rows) => rows.map((row) => row.id === item.id ? { ...row, assessor_comment: event.target.value } : row))} placeholder="What did you check? Did the evidence and proposed fix match?" /></label>
      <div className="decision-actions"><span className="ai-auto-status">{item.ai_analysis ? "Your role: verify Qwen’s guidance, then decide" : aiRunningIds.includes(item.id) ? "Qwen is analyzing…" : "Waiting for Qwen analysis"}</span><button className="secondary" onClick={() => void decideFinding(item, "needs_review")}>Keep for review</button><button className="secondary" onClick={() => void decideFinding(item, "rejected")}>Reject finding</button><button className="primary" disabled={!item.ai_analysis} title={!item.ai_analysis ? "Qwen analysis is required before confirmation" : "Confirm after verifying Qwen’s finding and fix"} onClick={() => void decideFinding(item, "confirmed")}>Confirm finding</button></div>
    </article>;
  }

  return <div className="shell">
    {mobileNav && <button className="nav-backdrop" aria-label="Close navigation" onClick={() => setMobileNav(false)} />}
    <aside className={`sidebar ${mobileNav ? "mobile-open" : ""}`}>
      <div className="brand"><span className="brandmark">WA</span><div><b>WEB ASSESSMENT</b><small>RESEARCH WORKSPACE</small></div><button className="mobileclose" aria-label="Close navigation" onClick={() => setMobileNav(false)}><IconX size={18} /></button></div>
      <div className="workspace-label">WORKSPACE</div>
      <nav>{nav.map((item) => <button key={item.label} onClick={() => { setSection(item.label); setMobileNav(false); }} className={section === item.label || (section === "New Assessment" && item.label === "Assessments") ? "nav active" : "nav"}><item.icon size={18} stroke={1.7} /><span>{item.label}</span>{item.label === "Vulnerability Findings" && <em>{findingsToReview}</em>}</button>)}</nav>
      <div className="sidebottom"><div className="access"><IconLock size={17} /><div><b>Authorized use only</b><small>Import scoped scanner evidence</small></div></div><div className="profile"><span>RA</span><div><b>Research assessor</b><small>{DEMO_MODE ? "Browser-only preview" : "Assessment workspace"}</small></div></div></div>
    </aside>

    <main><header className="topbar"><button className="mobilemenu" aria-label="Open navigation" onClick={() => setMobileNav(true)}><IconMenu2 /></button><div className="crumb">ASSESSMENT WORKSPACE <IconChevronRight size={14} /> {titles[section].toUpperCase()}</div><div className="header-right"><button className={`settings-shortcut${section === "Settings" ? " active" : ""}`} title="Settings" aria-label="Workspace settings" onClick={() => { setSection("Settings"); setSettingsView("Target & scope"); }}><IconSettings size={17} /></button><span className="env"><i /> {DEMO_MODE ? "DEMO PREVIEW" : "LIVE WORKSPACE"}</span><button className="avatar" aria-label="Local assessor">RA</button></div></header>
      <div className="content">
        {section !== "Assessment Progress" && <div className="pagehead"><div><div className="eyebrow">AUTHORIZED SECURITY ASSESSMENT</div><h1>{titles[section]}</h1><p>{section === "Dashboard" ? "Recent assessments and findings that need review." : section === "New Assessment" ? "Upload scanner evidence for an authorized target." : section === "Vulnerability Findings" ? "Review scanner evidence, AI guidance, and assessor decisions." : "Review assessment activity and saved evidence."}</p></div>{section !== "New Assessment" && <button className="primary page-action" onClick={section === "Settings" ? openRegisterForm : startNewAssessment}><IconPlus size={17} />{section === "Settings" ? "Register target" : "New assessment"}</button>}</div>}
        {notice && <div className={`notice${noticeError ? " error" : ""}`} role={noticeError ? "alert" : "status"}><span>{noticeError && aiError ? "AI analysis couldn't run. Check the AI service in Settings." : notice}</span><button className="notice-close" aria-label="Dismiss message" onClick={() => { setNotice(""); setNoticeError(false); }}><IconX size={15} /></button></div>}

        {section === "Dashboard" && <>
          <div className="stat-grid dashboard-stats">
            <article className="stat"><div>TOTAL ASSESSMENTS <IconListDetails size={17} /></div><strong>{assessmentCounts.all}</strong><small>Imported ZAP reports</small></article>
            <article className="stat"><div>FINDINGS TO REVIEW <IconAlertTriangle size={17} /></div><strong>{findingsToReview}</strong><small>Awaiting your decision</small></article>
            <article className="stat"><div>CONFIRMED FINDINGS <IconCircleCheck size={17} /></div><strong>{confirmedFindings}</strong><small>Confirmed by an assessor</small></article>
          </div>
          <div className="sectionrow assessment-toolbar"><div><h2>Assessment history</h2><p>Live records from your assessment database.</p></div><button className="textbutton" onClick={() => setSection("Assessments")}>All assessments <IconChevronRight size={15} /></button></div>
          <div className="table-tools"><label className="search-field"><IconSearch size={16} /><input value={assessmentSearch} onChange={(event) => setAssessmentSearch(event.target.value)} placeholder="Search targets or reports" /></label><span className="result-count">{filteredAssessments.length} assessments</span></div>
          {assessmentTable(filteredAssessments, true)}
        </>}

        {section === "Assessment Progress" && <section className="panel assessment-progress">
          <div className="progress-header"><div className={`progress-icon ${processingPhase === "complete" ? "complete" : "loading"}`}><IconActivity size={21} /></div><div className="progress-title"><div className="eyebrow">ASSESSMENT IMPORT</div><h2>{processingPhase === "upload" ? "Uploading and validating report" : processingPhase === "analysis" ? "Analyzing imported findings" : "Findings are ready"}</h2><p>{processingTargetName} · {processingFindingCount} finding instances</p></div><span className={`pill ${processingPhase === "complete" ? "completed" : "processing"}`}><i />{processingPhase === "complete" ? "Ready to review" : "Processing"}</span></div>
          <div className="progress-summary"><span>Assessment progress</span><b>{processingPercent}%</b></div><div className="assessment-progress-bar" role="progressbar" aria-valuenow={processingPercent} aria-valuemin={0} aria-valuemax={100}><span className={processingPhase === "complete" ? "" : "indeterminate"} style={{ width: `${processingPercent}%` }} /></div>
          <div className="progress-steps">
            <div className="progress-step done"><span>✓</span><div><b>Upload ZAP JSON</b><small>Report received</small></div><em>Complete</em></div>
            <div className="progress-step done"><span>✓</span><div><b>Validate target scope</b><small>Out-of-scope URLs filtered</small></div><em>Complete</em></div>
            <div className={`progress-step ${processingPhase === "analysis" ? "active" : processingPhase === "complete" && !aiError ? "done" : ""}`}><span>{processingPhase === "complete" && !aiError ? "✓" : "3"}</span><div><b>AI analysis</b><small>{aiError ? "Service unavailable; findings are still available" : processingPhase === "complete" ? "Analysis attempt finished" : processingAiRunning ? "Reviewing imported evidence" : "Starting analysis"}</small></div><em>{aiError ? "Unavailable" : processingPhase === "complete" ? "Complete" : "In progress"}</em></div>
            <div className="progress-step"><span>4</span><div><b>Human review</b><small>Confirm or reject each finding</small></div><em>Next</em></div>
            <div className="progress-step"><span>5</span><div><b>Assessment report</b><small>Generated from reviewed findings</small></div><em>After review</em></div>
          </div>
          <div className="progress-note">This imports a report generated in ZAP. It does not start a live scan, and AI never confirms findings.</div>
          {aiError && <div className="progress-ai-note">AI analysis could not complete. You can still inspect the ZAP evidence and make human review decisions.</div>}
          <button className="secondary progress-review" onClick={() => { setFindingScanFilter(processingScanId); setFindingPathFilter(""); setSection("Vulnerability Findings"); setProcessingScanId(""); setProcessingDataReady(false); }} disabled={!processingScanId}>View findings</button>
        </section>}

        {section === "New Assessment" && <>
          {targets.length > 1 && <label className="target-selector">Import report for<select value={registered?.id ?? ""} onChange={(event) => setRegistered(targets.find((item) => item.id === event.target.value) ?? null)}>{targets.map((item) => <option key={item.id} value={item.id}>{item.name} · {new URL(item.url).hostname}</option>)}</select></label>}
          {registered ? <>
            <section className="panel import-workflow"><div className="eyebrow">ASSESSOR WORKFLOW · {registered.name}</div><h2>Import an OWASP ZAP JSON report</h2><p>Choose a report generated for <b>{new URL(registered.url).hostname}</b>. Only entries matching the saved scope are imported. Uploading does not launch ZAP or scan the website.</p><label className="primary import-upload"><IconUpload size={17} />{busy ? "Importing report…" : "Choose ZAP JSON report"}<input type="file" accept=".json,application/json" disabled={busy} onChange={importZap} /></label><small className="import-help">Each imported finding starts as Needs Review. AI analysis never confirms vulnerabilities.</small></section>
            <section className="workflow-steps" aria-label="Assessment workflow"><div className="workflow-step current"><span>01</span><b>Upload ZAP JSON</b><small>Local scanner export</small></div><div className="workflow-step"><span>02</span><b>Parse & validate</b><small>Scope-filtered evidence</small></div><div className="workflow-step"><span>03</span><b>AI analysis</b><small>Advisory explanations</small></div><div className="workflow-step"><span>04</span><b>Human review</b><small>Confirm or reject</small></div><div className="workflow-step"><span>05</span><b>Report</b><small>Reviewed results</small></div></section>
            <section className="panel selected-target"><IconGlobe size={18} /><div><b>{registered.name}</b><a href={registered.url} target="_blank" rel="noreferrer">{registered.url}</a></div><button className="textbutton" onClick={() => { setSection("Settings"); setSettingsView("Target & scope"); }}>Review scope</button></section>
          </> : <section className="panel empty-state"><div className="empty-icon"><IconGlobe /></div><h2>Register an authorized target first</h2><p>Assessment reports are attached to a target and filtered against its approved URL scope.</p><button className="primary" onClick={openRegisterForm}><IconPlus size={16} /> Register target</button></section>}
        </>}

        {section === "Assessments" && <>
          <div className="assessment-controls"><div className="filter-tabs" aria-label="Filter assessments">{["All", "Processing", "Needs Review", "Completed", "Failed"].map((filter) => <button key={filter} className={assessmentFilter === filter ? "selected" : ""} onClick={() => setAssessmentFilter(filter)}>{filter}{filter === "All" ? ` (${assessmentCounts.all})` : ` (${filter === "Needs Review" ? assessmentCounts.needsReview : filter === "Processing" ? assessmentCounts.processing : filter === "Completed" ? assessmentCounts.completed : assessmentCounts.failed})`}</button>)}</div><label className="search-field"><IconSearch size={16} /><input value={assessmentSearch} onChange={(event) => setAssessmentSearch(event.target.value)} placeholder="Search target..." /></label></div>
          {assessmentTable(filteredAssessments)}
          <div className="table-footer">Showing {filteredAssessments.length} of {scans.length} assessments</div>
        </>}

        {section === "Vulnerability Findings" && <>
          <div className="finding-controls"><label className="search-field"><IconSearch size={16} /><input value={findingSearch} onChange={(event) => setFindingSearch(event.target.value)} placeholder="Search vulnerability, URL, evidence..." /></label><label className="select-filter"><IconFilter size={15} /><select value={findingSeverityFilter} onChange={(event) => setFindingSeverityFilter(event.target.value)}><option>All severities</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option><option>Informational</option></select></label><label className="select-filter"><select value={findingReviewFilter} onChange={(event) => setFindingReviewFilter(event.target.value)}><option>All review states</option><option value="needs_review">Needs review</option><option value="confirmed">Confirmed</option><option value="rejected">Rejected</option></select></label></div>
          {(findingPathFilter || findingScanFilter) && <div className="finding-filter"><span>{findingScanFilter ? `Showing findings from ${scans.find((scan) => scan.id === findingScanFilter)?.source ?? "selected assessment"}` : `Showing findings for ${findingPathFilter}`}</span><button className="textbutton" onClick={() => { setFindingPathFilter(""); setFindingScanFilter(""); }}>Clear assessment filter</button></div>}
          {selectedFinding ? <><button className="back-link" onClick={() => setSelectedFindingId("")}><IconArrowLeft size={16} /> Back to findings</button>{renderFindingCard(selectedFinding)}</> : filteredFindings.length ? <>
            <div className="finding-table-heading"><div><h2>Finding directory</h2><p>{filteredFindings.length} scanner observations · review each instance against its evidence</p></div></div>
            <div className="table-scroll"><table className="data-table findings-table"><thead><tr><th>Vulnerability</th><th>Qwen severity</th><th>Affected instances</th><th>Affected endpoint</th><th>Evidence</th><th>AI analysis</th><th>Human review</th><th /></tr></thead><tbody>{filteredFindings.map((item) => { const instanceCount = findings.filter((candidate) => candidate.scan_id === item.scan_id && candidate.title === item.title && candidate.category === item.category && candidate.scanner_severity === item.scanner_severity).length; const suggestedSeverity = item.ai_analysis?.result.suggested_severity; const displaySeverity = suggestedSeverity && suggestedSeverity !== "unknown" ? suggestedSeverity : item.scanner_severity; return <tr key={item.id}><td><b>{item.title}</b><small>{item.category}{Boolean(item.classification.cwe) ? ` · CWE ${String(item.classification.cwe)}` : ""}</small></td><td><span className={`severity-tag ${displaySeverity.toLowerCase()}`}>{suggestedSeverity && suggestedSeverity !== "unknown" ? suggestedSeverity : `ZAP: ${item.scanner_severity}`}</span></td><td>{instanceCount}</td><td className="endpoint-cell">{item.url}</td><td className="evidence-cell">{plainText(item.evidence) || "No instance evidence"}</td><td><span className={`ai-state ${item.ai_analysis ? "complete" : aiError ? "unavailable" : ""}`}>{item.ai_analysis ? "Analyzed" : aiRunningIds.includes(item.id) ? "Analyzing" : aiError ? "Unavailable" : "Pending"}</span></td><td><span className={`decision ${item.verification}`}>{item.verification.replace("_", " ")}</span></td><td><button className="table-action" onClick={() => setSelectedFindingId(item.id)}>Review</button></td></tr>; })}</tbody></table></div>
          </> : <section className="panel empty-state"><div className="empty-icon"><IconAlertTriangle /></div><h2>{findings.length ? "No findings match these filters" : "No findings imported"}</h2><p>{findings.length ? "Change or clear your filters to see findings." : "Upload a ZAP JSON report to build the review directory."}</p>{!findings.length && <button className="primary" onClick={startNewAssessment}><IconUpload size={16} /> New assessment</button>}</section>}
        </>}

        {section === "Reports" && (scans.length ? <div className="report-list">{scans.map((scan) => { const stats = statsFor(scan); const info = targetFor(scan); return <article className="panel report-row" key={scan.id}><div className="report-icon"><IconFileText /></div><div className="report-main"><b>{info?.name ?? "Assessment report"}</b><p>{scan.source} · {new Date(scan.created_at).toLocaleString()}</p><div className="audit-summary"><span>{scan.findings_count} findings</span><span>{stats.needsReview} needs review</span><span>{stats.rows.filter((item) => item.verification === "confirmed").length} confirmed</span></div></div><div className="report-actions"><a className="secondary" href={`${API}/reports/${scan.id}/pdf`} target="_blank" rel="noreferrer">Open PDF report</a><button className="clear-audit" onClick={() => setDeleteAuditTarget(scan)}>Clear audit</button></div></article>; })}</div> : <section className="panel empty-state"><div className="empty-icon"><IconFileText /></div><h2>No reports available</h2><p>Import scanner evidence and review findings before opening an assessment report.</p><button className="primary" onClick={startNewAssessment}><IconUpload size={16} /> New assessment</button></section>)}

        {section === "Settings" && <>
          <div className="settings-tabs"><button className={settingsView === "Target & scope" ? "selected" : ""} onClick={() => setSettingsView("Target & scope")}>Target & scope</button><button className={settingsView === "Connected services" ? "selected" : ""} onClick={() => setSettingsView("Connected services")}>Connected services</button></div>
          {settingsView === "Target & scope" && <>
            {targets.length > 1 && <label className="target-selector">Selected target<select value={registered?.id ?? ""} onChange={(event) => setRegistered(targets.find((item) => item.id === event.target.value) ?? null)}>{targets.map((item) => <option key={item.id} value={item.id}>{item.name} · {new URL(item.url).hostname}</option>)}</select></label>}
            {registered ? <><section className="panel target-card"><div className="target-card-head"><div className="target-symbol"><IconGlobe /></div><div><h2>{registered.name}</h2><a href={registered.url} target="_blank" rel="noreferrer">{registered.url}</a></div><span className="status connected"><i />Authorization recorded</span></div><div className="target-details">{!DEMO_MODE && <div><b>AUTHORIZED CONTACT</b><span>{registered.owner_contact}</span></div>}{registered.application_description && <div><b>APPLICATION</b><span>{registered.application_description}</span></div>}<div><b>IN-SCOPE URLS</b><span>{registered.in_scope.join(", ")}</span></div>{registered.out_of_scope.length > 0 && <div><b>OUT-OF-SCOPE URLS</b><span>{registered.out_of_scope.join(", ")}</span></div>}</div><div className="target-callout"><IconLock size={15} />Uploaded observations outside the saved scope are excluded from this workspace.</div></section>
              <section className="panel directory-panel"><div className="directory-heading"><div><h2>Finding path directory</h2><p>Report URLs with imported findings and assessor review status.</p></div></div>{(() => { const directory = new Map<string, Finding[]>(); findings.forEach((item) => { const path = endpointPath(item.url); directory.set(path, [...(directory.get(path) ?? []), item]); }); const rows = [...directory.entries()].sort(([a], [b]) => a.localeCompare(b)); return rows.length ? <div className="directory-list">{rows.map(([path, items]) => <article className="directory-row" key={path}><div className="directory-path"><a href={items[0].url} target="_blank" rel="noreferrer">{path}</a><small>Seen in {new Set(items.map((item) => item.scan_id)).size} imported report(s)</small></div><span className="directory-count">{items.length} finding instances</span><span className="directory-count">{items.filter((item) => item.ai_analysis).length} AI analyses</span><span className="directory-count">{items.filter((item) => item.verification !== "needs_review").length} human reviewed</span><button className="secondary" onClick={() => { setFindingPathFilter(path); setSection("Vulnerability Findings"); }}>Review</button></article>)}</div> : <p className="directory-empty">Imported report URLs will appear here after your first assessment.</p>; })()}</section></> : <section className="panel empty-state"><div className="empty-icon"><IconGlobe /></div><h2>No targets registered</h2><p>Register a target, confirm authorization, and define its scope before importing a report.</p><button className="primary" onClick={openRegisterForm}><IconPlus size={16} /> Register target</button></section>}
          </>}
          {settingsView === "Connected services" && <><div className="service-toolbar"><p>Live health checks refresh every 15 seconds.</p><button className="secondary" onClick={() => void refreshHealth()}><IconRefresh size={15} /> Refresh status</button></div><div className="service-grid">{services.map((service) => { const value = health?.services[service.key]; return <article className="service" key={service.key}><service.icon size={18} /><div className="servicetext"><b>{service.name}</b><small>{value?.detail ?? "Checking connection…"}</small></div><span className={`status ${value?.status ?? "starting"}`}><i />{value?.status === "ready" ? "Ready for JSON Import" : value?.status ?? "starting"}</span></article>; })}</div><div className="footnote"><IconLock size={16} /><span>A connected status reflects the API health response; it does not guarantee that every model request will succeed.</span></div></>}
        </>}
      </div>
    </main>

    {showForm && <div className="modal-backdrop" role="presentation">
      <form className={`modal ${formMode === "assessment" ? "assessment-modal" : ""}`} autoComplete="off" onSubmit={formMode === "assessment" ? submitAssessment : submit}>
        <div className="modalhead"><div><div className="eyebrow">{formMode === "assessment" ? "NEW ASSESSMENT" : "TARGET REGISTRATION"}</div><h2>{formMode === "assessment" ? "Set up assessment & import report" : DEMO_MODE ? "Add a website URL" : "Define authorization and scope"}</h2></div><button type="button" className="close" aria-label="Close" onClick={() => setShowForm(false)}><IconX /></button></div>
        {formMode === "assessment" ? <p className="formintro">Choose a saved target or enter a new one, then attach its ZAP JSON report. Nothing starts a live scan.</p> : DEMO_MODE ? <p className="formintro">Browser-only preview. This saves the URL on this device; it does not contact or validate the site.</p> : <p className="formintro">Review the target details and scope. This step does not start a scan.</p>}
        {formMode === "assessment" && targets.length > 0 && <label>Assessment target<select value={assessmentTargetId} onChange={(event) => {
          const id = event.target.value;
          setAssessmentTargetId(id);
          const chosen = targets.find((row) => row.id === id);
          if (chosen) setTarget({ name: chosen.name, url: chosen.url, application_description: chosen.application_description, owner_contact: chosen.owner_contact, authorized: true, in_scope: chosen.in_scope.join("\n"), out_of_scope: chosen.out_of_scope.join("\n") });
          else setTarget({ name: "", url: "", application_description: "", owner_contact: "", authorized: false, in_scope: "", out_of_scope: "" });
        }}><option value="new">Register a new target</option>{targets.map((row) => <option key={row.id} value={row.id}>{row.name} · {new URL(row.url).hostname}</option>)}</select></label>}
        {formMode === "assessment" && selectedAssessmentTarget && <section className="assessment-target-summary"><IconGlobe size={18} /><div><b>{selectedAssessmentTarget.name}</b><span>{selectedAssessmentTarget.url}</span><small>{selectedAssessmentTarget.in_scope.length} in-scope URL{selectedAssessmentTarget.in_scope.length === 1 ? "" : "s"} saved</small></div></section>}
        {(formMode === "target" || (formMode === "assessment" && !selectedAssessmentTarget)) && <>
          {formMode === "target" && !DEMO_MODE && <button type="button" className="textbutton" onClick={openRegisterForm}>Use Contnental Fitness Gym details</button>}
          {!DEMO_MODE && <><label>Target name<input required minLength={2} value={target.name} onChange={(event) => setTarget({ ...target, name: event.target.value })} placeholder="e.g. Staging web application" autoComplete="organization" /></label><label>Application description <small>What does the site do?</small><textarea rows={2} maxLength={2000} value={target.application_description} onChange={(event) => setTarget({ ...target, application_description: event.target.value })} placeholder="e.g. Customer booking portal" /></label></>}
          <label>Website URL<input required type="url" value={target.url} onChange={(event) => setTarget({ ...target, url: event.target.value })} placeholder="https://example.org" autoComplete="url" /></label>
          {!DEMO_MODE && <><label>Owner or authorized contact<input required value={target.owner_contact} onChange={(event) => setTarget({ ...target, owner_contact: event.target.value })} placeholder="Name or contact details" autoComplete="name" /></label><label>In-scope URLs <small>One URL per line. Must use the registered host.</small><textarea required rows={2} value={target.in_scope} onChange={(event) => setTarget({ ...target, in_scope: event.target.value })} placeholder="https://example.org/" /></label><label>Out-of-scope URLs <small>One per line</small><textarea rows={2} value={target.out_of_scope} onChange={(event) => setTarget({ ...target, out_of_scope: event.target.value })} placeholder="https://example.org/billing" /></label></>}
          <label className="check"><input type="checkbox" checked={target.authorized} onChange={(event) => setTarget({ ...target, authorized: event.target.checked })} />I confirm I have explicit permission to assess this target{DEMO_MODE ? "." : " and the listed scope."}</label>
        </>}
        {formMode === "assessment" && <label className="report-picker"><span>OWASP ZAP JSON report <small>Choose the exported .json file to import.</small></span><input type="file" accept=".json,application/json" required onChange={(event) => setAssessmentFile(event.target.files?.[0] ?? null)} />{assessmentFile && <small className="selected-file">{assessmentFile.name}</small>}</label>}
        {notice && <div className="formerror" role="alert">{formMode === "assessment" && noticeError && aiError ? "The AI service is unavailable. The report can still be imported and findings reviewed." : notice}</div>}
        <div className="modalactions"><button type="button" className="secondary" disabled={busy} onClick={() => setShowForm(false)}>Cancel</button><button className="primary" disabled={busy || !target.authorized || (formMode === "assessment" && !assessmentFile)}>{busy ? formMode === "assessment" ? "Saving & importing…" : DEMO_MODE ? "Saving…" : "Checking…" : formMode === "assessment" ? selectedAssessmentTarget ? "Import report" : "Validate & import" : DEMO_MODE ? "Save preview target" : "Validate target"}</button></div>
      </form>
    </div>}

    {deleteAuditTarget && <div className="modal-backdrop" role="presentation"><section className="modal" role="alertdialog" aria-modal="true" aria-labelledby="clear-audit-title"><div className="modalhead"><div><div className="eyebrow">CLEAR IMPORTED AUDIT</div><h2 id="clear-audit-title">Remove this audit and its findings?</h2></div><button type="button" className="close" aria-label="Close" onClick={() => setDeleteAuditTarget(null)}><IconX /></button></div><p className="formintro">This permanently removes <b>{deleteAuditTarget.findings_count} findings</b> from {targetFor(deleteAuditTarget)?.name ?? "the selected target"}, including AI explanations and Confirm/Reject decisions. It does not remove the target or other audits.</p>{noticeError && notice && <div className="formerror" role="alert">{notice}</div>}<div className="modalactions"><button type="button" className="secondary" disabled={busy} onClick={() => setDeleteAuditTarget(null)}>Cancel</button><button type="button" className="clear-audit" disabled={busy} onClick={() => void clearAudit(deleteAuditTarget)}>{busy ? "Clearing…" : "Clear audit and findings"}</button></div></section></div>}
  </div>;
}
