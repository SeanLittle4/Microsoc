import { useState, useMemo } from "react";

// ─── Design tokens ────────────────────────────────────────────────────────────
const BG       = "#0b1117";
const CARD     = "#0e1822";
const BORDER   = "#141e28";
const BORDER2  = "#1e2e3e";
const GOLD     = "#c8922a";
const TEXT_PRI = "#e8ddd0";
const TEXT_SEC = "#8a9eb0";
const TEXT_DIM = "#3a5568";
const TEXT_MUT = "#3b5b79";
const CRIT     = "#e05c5c";
const HIGH_C   = "#e8a020";
const MED_C    = "#5b8dd4";
const LOW_C    = "#60b06e";
const SEV_COLORS = { critical: CRIT, high: HIGH_C, medium: MED_C, low: LOW_C };

// ─── Gordon-Loeb constant ─────────────────────────────────────────────────────
const GL_CAP = 1 / Math.E; // ≈ 0.3679

// ─── CVSS v3.1 exploitability weights ────────────────────────────────────────
// Source: NIST NVD CVSS v3.1 specification
// https://www.first.org/cvss/specification-document
const AV_W = { network: 0.85, adjacent: 0.62, local: 0.55, physical: 0.2 };
const AC_W = { low: 0.77, high: 0.44 };
const PR_W = { none: 0.85, low: 0.62, high: 0.27 };
const UI_W = { none: 0.85, required: 0.62 };

// Maximum possible product of AV × AC × PR × UI (network/low/none/none)
const MAX_EXPLOIT = 0.85 * 0.77 * 0.85 * 0.85; // ≈ 0.4729

// ─── Severity impact weights (calibrated to Gordon-Loeb scale) ────────────────
// These represent the impact component of each finding's v contribution.
// Exploitability (CVSS) and impact (severity) are multiplied together.
const SEV_W = { critical: 0.18, high: 0.10, medium: 0.05, low: 0.02 };

// Fallback likelihood multiplier for manually-added findings (no CVSS data)
const LIKE_M = { high: 1.0, medium: 0.75, low: 0.5 };

// Severity ordering used for confidence interval bounds (±1 grade)
const SEV_ORDER = ["low", "medium", "high", "critical"];

// ─── Empty model fallback ─────────────────────────────────────────────────────
const EMPTY_MODEL = {
  findings: [],
  summary: { overall_risk_score: 0, total_findings: 0, critical: 0, high: 0, medium: 0, low: 0 },
};

// ─── Helpers ──────────────────────────────────────────────────────────────────
const fmt = (n) =>
  Number.isFinite(n)
    ? n.toLocaleString("en-US", { style: "currency", currency: "USD", maximumFractionDigits: 0 })
    : "—";

const pct = (n) => (Number.isFinite(n) ? `${(n * 100).toFixed(1)}%` : "—");

// Returns the normalised CVSS exploitability score [0, 1] for a finding.
// Findings from the survey carry cvss_av/ac/pr/ui; manual findings do not.
function cvssExploitability(f) {
  const av = AV_W[f.cvss_av];
  const ac = AC_W[f.cvss_ac];
  const pr = PR_W[f.cvss_pr];
  const ui = UI_W[f.cvss_ui];
  if (av == null || ac == null || pr == null || ui == null) return null;
  return (av * ac * pr * ui) / MAX_EXPLOIT;
}

// Per-finding v contribution.
// Survey findings: SEV_W[severity] × normalised_cvss_exploitability
// Manual findings: SEV_W[severity] × LIKE_M[likelihood]  (legacy behaviour)
function findingContribution(f, overrideSev) {
  const sev = overrideSev ?? f.severity;
  const impact = SEV_W[sev] ?? 0;
  const exploit = cvssExploitability(f);
  if (exploit !== null) return impact * exploit;
  return impact * (LIKE_M[f.likelihood] ?? 0.5);
}

// Sum contributions across all findings, capped at 0.95
function computeV(findings, overrideSev) {
  const raw = (findings ?? []).reduce((sum, f) => sum + findingContribution(f, overrideSev), 0);
  return Math.min(raw, 0.95);
}

// Confidence interval: shift every finding's severity ±1 grade.
// v_low  = all findings assumed one severity grade lower (conservative)
// v_high = all findings assumed one severity grade higher (worst-case)
// This reflects the inherent uncertainty in qualitative severity classification.
function computeVBounds(findings) {
  const shifted = (dir) =>
    (findings ?? []).reduce((sum, f) => {
      const idx = SEV_ORDER.indexOf(f.severity);
      const newSev = SEV_ORDER[Math.max(0, Math.min(SEV_ORDER.length - 1, idx + dir))];
      return sum + findingContribution(f, newSev);
    }, 0);
  return {
    low:  Math.min(shifted(-1), 0.95),
    high: Math.min(shifted(+1), 0.95),
  };
}

function findingWeight(f) {
  return findingContribution(f);
}

// ─── Survey context maps ──────────────────────────────────────────────────────
const CROWN_JEWEL_HINTS = {
  "Theft of customer data — lawsuits, lost trust, regulatory fines":
    "Customer PII breach (notification, legal fees, regulatory fines)",
  "Loss of access to our systems — unable to operate for days or weeks":
    "Operational downtime (lost revenue + recovery costs)",
  "Theft of money directly from bank or payment accounts":
    "Direct financial fraud / wire transfer loss",
  "Exposure of confidential contracts, pricing, or business strategies":
    "Intellectual property / trade secret exposure",
  "Reputational damage from public breach notification":
    "Reputational damage (lost customers, PR, brand recovery)",
  "Regulatory penalties for non-compliance with data protection laws":
    "Regulatory fines and compliance costs",
};

const BREACH_COST_MAP = {
  "Less than $10,000 — even a small incident could be catastrophic":
    "You indicated your business can absorb less than $10,000 before facing an existential threat. Even a modest breach would be catastrophic — ensuring your total potential loss figure is realistic and complete is especially important.",
  "$10,000 – $50,000 — significant but we might survive":
    "Your loss tolerance is $10,000–$50,000. Your total potential loss (L) should reflect what a breach would actually cost — not just what you can withstand. These two numbers are often very different.",
  "$50,000 – $250,000 — painful but recoverable":
    "You could survive losses up to $250,000. Recovery, legal, downtime, and notification costs often exceed initial estimates — use the categories below to build a realistic L.",
  "More than $250,000 — we have financial resilience":
    "You have higher financial resilience than most SMEs. Still, use the categories below to estimate total breach cost accurately — the Gordon-Loeb model works best with realistic figures.",
};

// ─── Shared UI ────────────────────────────────────────────────────────────────
const SectionLabel = ({ children }) => (
  <div style={{
    color: TEXT_MUT, fontSize: 10, fontFamily: "monospace",
    textTransform: "uppercase", letterSpacing: "0.1em", marginBottom: 10,
  }}>
    {children}
  </div>
);

const Divider = () => (
  <div style={{ height: 1, background: BORDER, margin: "32px 0" }} />
);

const FormulaBox = ({ children }) => (
  <div style={{
    background: BG, border: `1px solid ${BORDER}`, borderRadius: 8,
    padding: "13px 18px", fontFamily: "monospace", fontSize: 13,
    color: GOLD, letterSpacing: "0.03em", margin: "14px 0",
  }}>
    {children}
  </div>
);

const InfoBox = ({ color = GOLD, children }) => (
  <div style={{
    background: color + "0d", border: `1px solid ${color}25`,
    borderLeft: `3px solid ${color}`, borderRadius: 8,
    padding: "14px 18px", marginTop: 16,
    color: TEXT_DIM, fontSize: 13, fontFamily: "Georgia, serif", lineHeight: 1.65,
  }}>
    {children}
  </div>
);

const StatBox = ({ label, value, sub, color }) => (
  <div style={{
    background: BG, border: `1px solid ${color ? color + "30" : BORDER}`,
    borderRadius: 8, padding: "14px 18px", flex: 1, minWidth: 130,
  }}>
    <div style={{ color: TEXT_MUT, fontSize: 10, fontFamily: "monospace", textTransform: "uppercase", letterSpacing: "0.07em", marginBottom: 5 }}>
      {label}
    </div>
    <div style={{ color: color || TEXT_PRI, fontSize: 20, fontWeight: 700, fontFamily: "monospace" }}>
      {value}
    </div>
    {sub && <div style={{ color: TEXT_MUT, fontSize: 10, fontFamily: "monospace", marginTop: 3 }}>{sub}</div>}
  </div>
);

const SevBadge = ({ sev }) => (
  <span style={{
    padding: "2px 7px", borderRadius: 4, flexShrink: 0,
    background: (SEV_COLORS[sev] || TEXT_MUT) + "18",
    border: `1px solid ${(SEV_COLORS[sev] || TEXT_MUT)}35`,
    color: SEV_COLORS[sev] || TEXT_MUT,
    fontSize: 9, fontFamily: "monospace", fontWeight: 700,
    textTransform: "uppercase", letterSpacing: "0.05em",
  }}>
    {sev}
  </span>
);

// ─── Confidence Interval Bar ──────────────────────────────────────────────────
function CIBar({ vLow, vCentral, vHigh, vColor }) {
  const margin = ((vHigh - vLow) / 2 * 100).toFixed(1);
  const hasCvss = vLow !== vCentral || vHigh !== vCentral;

  return (
    <div style={{ marginBottom: 16 }}>
      {/* Range bar */}
      <div style={{ position: "relative", height: 10, background: BORDER, borderRadius: 5, overflow: "visible", marginBottom: 8 }}>
        {/* Filled range: low → high */}
        <div style={{
          position: "absolute",
          left: `${vLow * 100}%`,
          width: `${(vHigh - vLow) * 100}%`,
          height: "100%",
          background: vColor + "40",
          borderRadius: 5,
        }} />
        {/* Central estimate marker */}
        <div style={{
          position: "absolute",
          left: `${vCentral * 100}%`,
          transform: "translateX(-50%)",
          width: 3, height: "100%",
          background: vColor,
          borderRadius: 2,
        }} />
        {/* Low bound marker */}
        <div style={{
          position: "absolute",
          left: `${vLow * 100}%`,
          transform: "translateX(-50%)",
          width: 2, height: 10,
          background: vColor + "80",
          borderRadius: 1,
        }} />
        {/* High bound marker */}
        <div style={{
          position: "absolute",
          left: `${vHigh * 100}%`,
          transform: "translateX(-50%)",
          width: 2, height: 10,
          background: vColor + "80",
          borderRadius: 1,
        }} />
      </div>

      {/* Labels under bar */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
        <div style={{ textAlign: "center", transform: `translateX(${vLow * 100 * 0.8}%)` }}>
          <div style={{ color: TEXT_MUT, fontSize: 9, fontFamily: "monospace" }}>{pct(vLow)}</div>
          <div style={{ color: TEXT_MUT, fontSize: 8, fontFamily: "monospace" }}>low</div>
        </div>
        <div style={{ textAlign: "center" }}>
          <div style={{ color: vColor, fontSize: 11, fontFamily: "monospace", fontWeight: 700 }}>
            {pct(vCentral)} {hasCvss && <span style={{ color: TEXT_MUT, fontWeight: 400 }}>± {margin}%</span>}
          </div>
          <div style={{ color: TEXT_MUT, fontSize: 8, fontFamily: "monospace" }}>central estimate</div>
        </div>
        <div style={{ textAlign: "center", transform: `translateX(-${(1 - vHigh) * 100 * 0.8}%)` }}>
          <div style={{ color: TEXT_MUT, fontSize: 9, fontFamily: "monospace" }}>{pct(vHigh)}</div>
          <div style={{ color: TEXT_MUT, fontSize: 8, fontFamily: "monospace" }}>high</div>
        </div>
      </div>

      {hasCvss && (
        <div style={{ color: TEXT_MUT, fontSize: 11, fontFamily: "Georgia, serif", lineHeight: 1.5, marginTop: 10 }}>
          The ±{margin}% interval reflects uncertainty in severity classification — each finding's grade could reasonably be one step higher or lower. The Gordon-Loeb investment ceiling (z*) is computed on the central estimate; you can see how it shifts across the range in the results section.
        </div>
      )}
    </div>
  );
}

// ─── CVSS attribute display badge ─────────────────────────────────────────────
function CVSSBadge({ label, value }) {
  if (!value) return null;
  return (
    <span style={{
      display: "inline-flex", alignItems: "center", gap: 4,
      padding: "2px 7px", borderRadius: 4, marginRight: 5, marginBottom: 4,
      background: BORDER2, border: `1px solid ${BORDER}`,
      fontSize: 9, fontFamily: "monospace", color: TEXT_SEC,
    }}>
      <span style={{ color: TEXT_MUT }}>{label}:</span>
      <span style={{ color: TEXT_SEC, fontWeight: 700, textTransform: "uppercase" }}>{value}</span>
    </span>
  );
}

// ─── Section 1: GL Introduction ───────────────────────────────────────────────
function GLIntro({ model }) {
  const [open, setOpen] = useState(false);
  const hasSurveyResults = model.summary.total_findings > 0;
  const { summary } = model;
  const scoreColor = summary.overall_risk_score >= 70 ? CRIT
    : summary.overall_risk_score >= 40 ? HIGH_C : LOW_C;

  return (
    <div style ={{color: TEXT_SEC}}>
      Each threat is scored based on how easy it is for an attacker to exploit, whether they need to be physically present, already have access, or can attack from anywhere on the internet. The scores are then added up to estimate the overall chance of a breach.
      {hasSurveyResults ? (
        <div style={{ display: "flex", alignItems: "center", gap: 20, flexWrap: "wrap", marginBottom: 20 }}>
          <div style={{ textAlign: "center" }}>
            <div style={{ fontSize: 44, fontWeight: 700, color: scoreColor, fontFamily: "monospace", lineHeight: 1 }}>
              {summary.overall_risk_score}
            </div>
            <div style={{ color: TEXT_MUT, fontSize: 9, fontFamily: "monospace", marginTop: 3 }}>RISK SCORE / 100</div>
          </div>
          <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
            {summary.critical > 0 && (
              <div style={{ padding: "8px 14px", borderRadius: 8, background: CRIT + "15", border: `1px solid ${CRIT}30`, textAlign: "center" }}>
                <div style={{ fontSize: 20, fontWeight: 700, color: CRIT, fontFamily: "monospace" }}>{summary.critical}</div>
                <div style={{ fontSize: 9, color: CRIT, fontFamily: "monospace" }}>CRITICAL</div>
              </div>
            )}
            {summary.high > 0 && (
              <div style={{ padding: "8px 14px", borderRadius: 8, background: HIGH_C + "15", border: `1px solid ${HIGH_C}30`, textAlign: "center" }}>
                <div style={{ fontSize: 20, fontWeight: 700, color: HIGH_C, fontFamily: "monospace" }}>{summary.high}</div>
                <div style={{ fontSize: 9, color: HIGH_C, fontFamily: "monospace" }}>HIGH</div>
              </div>
            )}
            {summary.medium > 0 && (
              <div style={{ padding: "8px 14px", borderRadius: 8, background: MED_C + "15", border: `1px solid ${MED_C}30`, textAlign: "center" }}>
                <div style={{ fontSize: 20, fontWeight: 700, color: MED_C, fontFamily: "monospace" }}>{summary.medium}</div>
                <div style={{ fontSize: 9, color: MED_C, fontFamily: "monospace" }}>MEDIUM</div>
              </div>
            )}
          </div>
          <div style={{ flex: 1, minWidth: 180 }}>
            <p style={{ color: TEXT_DIM, fontSize: 13, fontFamily: "Georgia, serif", lineHeight: 1.65, margin: 0 }}>
              Your {summary.total_findings} confirmed findings have been automatically fed into the{" "}
              <strong style={{ color: GOLD }}>Gordon–Loeb Model</strong>. Breach probability (v) is now computed
              using <strong style={{ color: TEXT_SEC }}>CVSS v3.1 exploitability attributes</strong> for each
              finding, with a confidence interval derived from severity classification uncertainty.
            </p>
          </div>
        </div>
      ) : (
        <InfoBox color={MED_C}>
          <strong style={{ color: TEXT_SEC }}>No survey results loaded.</strong> Add your own vulnerabilities below using severity and likelihood, or set the breach probability (v) manually with the override slider. Enter your asset value to compute your investment ceiling.
        </InfoBox>
      )}

      <button
        onMouseDown={e => e.preventDefault()}
        onClick={() => setOpen(o => !o)}
        style={{
          display: "flex", alignItems: "center", gap: 10, width: "100%",
          background: "none", border: `1px solid ${BORDER}`, borderRadius: 8,
          padding: "10px 16px", cursor: "pointer", textAlign: "left", userSelect: "none",
          marginTop: hasSurveyResults ? 0 : 16,
        }}
      >
        <span style={{ color: TEXT_MUT, fontSize: 10, fontFamily: "monospace", textTransform: "uppercase", letterSpacing: "0.08em", flex: 1 }}>
          About the Gordon–Loeb Model &amp; CVSS v3.1 Scoring
        </span>
        <span style={{ color: TEXT_MUT, fontSize: 12 }}>{open ? "▲" : "▼"}</span>
      </button>

      {open && (
        <div style={{ background: BG, border: `1px solid ${BORDER}`, borderTop: "none", borderRadius: "0 0 8px 8px", padding: "18px" }}>
          <p style={{ color: TEXT_DIM, fontSize: 13, fontFamily: "Georgia, serif", lineHeight: 1.7, margin: "0 0 12px" }}>
            Published in <em>ACM Transactions on Information and System Security</em> (2002), the Gordon-Loeb model
            proves that the rational investment ceiling is <strong style={{ color: GOLD }}>1/e ≈ 36.8%</strong> of
            expected loss. Every dollar below this threshold has positive expected return; beyond it, diminishing
            returns apply.
          </p>
          <FormulaBox>z* ≤ (1/e) × v × L &nbsp;&nbsp;≈&nbsp;&nbsp; 0.3679 × v × L</FormulaBox>

          <p style={{ color: TEXT_DIM, fontSize: 13, fontFamily: "Georgia, serif", lineHeight: 1.7, margin: "12px 0" }}>
            <strong style={{ color: TEXT_SEC }}>How v is computed.</strong> Each survey finding carries four
            CVSS v3.1 exploitability attributes: Attack Vector (AV), Attack Complexity (AC), Privileges Required
            (PR), and User Interaction (UI). These are multiplied together and normalised to [0, 1], then scaled
            by the finding's severity impact weight. All findings' contributions are summed and capped at 0.95.
          </p>
          <FormulaBox>
            v_contribution = SEV_impact × (AV × AC × PR × UI) / max_exploit{"\n"}
            v = min(Σ contributions, 0.95)
          </FormulaBox>

          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(200px, 1fr))", gap: 10, marginTop: 14 }}>
            {[
              { attr: "AV — Attack Vector",       vals: "Network 0.85 · Adjacent 0.62 · Local 0.55 · Physical 0.20" },
              { attr: "AC — Attack Complexity",   vals: "Low 0.77 · High 0.44" },
              { attr: "PR — Privileges Required", vals: "None 0.85 · Low 0.62 · High 0.27" },
              { attr: "UI — User Interaction",    vals: "None 0.85 · Required 0.62" },
            ].map(({ attr, vals }) => (
              <div key={attr} style={{ background: CARD, border: `1px solid ${BORDER}`, borderRadius: 6, padding: "10px 12px" }}>
                <div style={{ color: GOLD, fontSize: 10, fontFamily: "monospace", fontWeight: 700, marginBottom: 4 }}>{attr}</div>
                <div style={{ color: TEXT_MUT, fontSize: 10, fontFamily: "monospace", lineHeight: 1.6 }}>{vals}</div>
              </div>
            ))}
          </div>

          <p style={{ color: TEXT_DIM, fontSize: 13, fontFamily: "Georgia, serif", lineHeight: 1.7, margin: "14px 0 0" }}>
            <strong style={{ color: TEXT_SEC }}>Confidence interval.</strong> The ± range is computed by
            shifting every finding's severity one grade up and one grade down, then recalculating v. This
            captures the inherent uncertainty in qualitative severity classification — a "high" finding
            could reasonably be critical or medium — without requiring precise probability estimates.
          </p>
        </div>
      )}
    </div>
  );
}

// ─── Section 2: Vulnerability (v) ────────────────────────────────────────────
function VulnerabilitySection({ model, extraFindings, setExtraFindings, manualV, setManualV }) {
  const hasSurveyResults = model.findings.length > 0;
  const [showExtra, setShowExtra] = useState(!hasSurveyResults);

  // Central v from all findings
  const allSurveyFindings = model.findings;
  const validExtra = extraFindings.filter(f => f.name);
  const allFindings = [...allSurveyFindings, ...validExtra];

  const baseV   = computeV(allSurveyFindings);
  const extraV  = computeV(validExtra);
  const bounds  = useMemo(() => computeVBounds(allFindings), [allFindings]);

  const combinedV  = manualV !== null ? manualV : Math.min(baseV + extraV, 0.95);
  const vLow       = manualV !== null ? manualV : bounds.low;
  const vHigh      = manualV !== null ? manualV : bounds.high;
  const vColor     = combinedV > 0.6 ? CRIT : combinedV > 0.3 ? HIGH_C : LOW_C;

  const hasExtras = extraFindings.length > 0 || manualV !== null;

  const addExtra = () =>
    setExtraFindings(f => [...f, { id: `extra-${Date.now()}`, name: "", severity: "high", likelihood: "medium" }]);
  const updateExtra = (id, field, val) =>
    setExtraFindings(f => f.map(x => x.id === id ? { ...x, [field]: val } : x));
  const removeExtra = (id) =>
    setExtraFindings(f => f.filter(x => x.id !== id));

  const selectStyle = {
    background: CARD, border: `1px solid ${BORDER}`, borderRadius: 6,
    color: TEXT_SEC, fontSize: 12, fontFamily: "monospace", padding: "6px 8px", cursor: "pointer",
  };

  return (
    <div>
      {/* Header */}
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", marginBottom: 14, flexWrap: "wrap", gap: 10 }}>
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 4 }}>
            <span style={{ color: GOLD, fontFamily: "monospace", fontSize: 10, fontWeight: 700, letterSpacing: "0.1em" }}>v</span>
            <span style={{ color: BORDER2, fontFamily: "monospace", fontSize: 10 }}>·</span>
            <span style={{ color: TEXT_MUT, fontFamily: "monospace", fontSize: 10 }}>
              Vulnerability — {hasSurveyResults ? "CVSS-weighted from findings" : "add findings or set manually"}
            </span>
          </div>
          <h3 style={{ color: TEXT_PRI, fontFamily: "Georgia, serif", fontSize: 18, fontWeight: 700, margin: 0, lineHeight: 1.2 }}>
            Breach Probability
          </h3>
        </div>
        <div style={{ textAlign: "right" }}>
          <div style={{ fontSize: 34, fontWeight: 700, color: combinedV > 0 ? vColor : TEXT_MUT, fontFamily: "monospace", lineHeight: 1 }}>
            {combinedV > 0 ? pct(combinedV) : "—"}
          </div>
          {combinedV > 0 && manualV === null && allFindings.length > 0 && (
            <div style={{ color: TEXT_MUT, fontSize: 10, fontFamily: "monospace", marginTop: 2 }}>
              ± {(((vHigh - vLow) / 2) * 100).toFixed(1)}%
            </div>
          )}
        </div>
      </div>

      {/* Confidence interval bar */}
      {combinedV > 0 && (
        <CIBar vLow={vLow} vCentral={combinedV} vHigh={vHigh} vColor={vColor} />
      )}

      {combinedV === 0 && (
        <p style={{ color: TEXT_DIM, fontSize: 13, fontFamily: "Georgia, serif", lineHeight: 1.65, margin: "0 0 16px" }}>
          Add risk factors below or use the manual override to set your breach probability.
        </p>
      )}

      {/* Survey findings breakdown */}
      {hasSurveyResults && (
        <div style={{ background: BG, border: `1px solid ${BORDER}`, borderRadius: 8, padding: "14px 18px", marginBottom: 14 }}>
          <SectionLabel>
            {model.findings.length} confirmed finding{model.findings.length !== 1 ? "s" : ""} — CVSS v3.1 exploitability
          </SectionLabel>
          {model.findings.map((f, i) => {
            const w = findingWeight(f);
            const exploit = cvssExploitability(f);
            const color = SEV_COLORS[f.severity] || TEXT_MUT;
            const barW = Math.min((w / (SEV_W.critical * 1)) * 100, 100);
            return (
              <div key={f.id} style={{
                padding: "10px 0",
                borderBottom: i < model.findings.length - 1 ? `1px solid ${BORDER}` : "none",
              }}>
                <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 6 }}>
                  <SevBadge sev={f.severity} />
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ color: TEXT_SEC, fontSize: 12, fontFamily: "Georgia, serif", fontWeight: 700, lineHeight: 1.3 }}>
                      {f.name}
                    </div>
                  </div>
                  <div style={{ flexShrink: 0, textAlign: "right", minWidth: 90 }}>
                    <div style={{ height: 4, width: 80, background: BORDER, borderRadius: 2, overflow: "hidden", marginBottom: 3 }}>
                      <div style={{ width: `${barW}%`, height: "100%", background: color, borderRadius: 2 }} />
                    </div>
                    <div style={{ color: color, fontSize: 10, fontFamily: "monospace", fontWeight: 700 }}>+{pct(w)}</div>
                  </div>
                </div>
                {/* CVSS attribute badges */}
                <div style={{ paddingLeft: 0, marginTop: 2 }}>
                  <CVSSBadge label="AV" value={f.cvss_av} />
                  <CVSSBadge label="AC" value={f.cvss_ac} />
                  <CVSSBadge label="PR" value={f.cvss_pr} />
                  <CVSSBadge label="UI" value={f.cvss_ui} />
                  {exploit !== null && (
                    <span style={{ fontSize: 9, fontFamily: "monospace", color: TEXT_MUT, marginLeft: 4 }}>
                      exploit score: {(exploit * 100).toFixed(0)}%
                    </span>
                  )}
                </div>
              </div>
            );
          })}
          <div style={{ display: "flex", justifyContent: "space-between", marginTop: 10, paddingTop: 8, borderTop: `1px solid ${BORDER}`, flexWrap: "wrap", gap: 6 }}>
            <span style={{ color: TEXT_MUT, fontSize: 11, fontFamily: "monospace" }}>
              Base v (CVSS-weighted):
            </span>
            <span style={{ color: vColor, fontSize: 13, fontFamily: "monospace", fontWeight: 700 }}>{pct(baseV)}</span>
          </div>
        </div>
      )}

      {/* Extra findings panel */}
      <button
        onMouseDown={e => e.preventDefault()}
        onClick={() => setShowExtra(o => !o)}
        style={{
          display: "flex", alignItems: "center", gap: 10, width: "100%",
          background: showExtra ? GOLD + "0d" : "none",
          border: `1px solid ${showExtra ? GOLD + "40" : BORDER}`,
          borderRadius: showExtra ? "8px 8px 0 0" : 8,
          padding: "10px 16px", cursor: "pointer", textAlign: "left",
          userSelect: "none", transition: "all 0.2s",
        }}
      >
        <span style={{
          color: showExtra ? GOLD : TEXT_MUT,
          fontSize: 10, fontFamily: "monospace",
          textTransform: "uppercase", letterSpacing: "0.08em", flex: 1,
        }}>
          {showExtra ? "▼" : "▸"}&nbsp;&nbsp;
          {hasSurveyResults ? "Additional Risk Factors & Manual Override" : "Add Vulnerabilities & Risk Factors"}
          {hasExtras && (
            <span style={{ color: HIGH_C, marginLeft: 10 }}>
              ({[
                extraFindings.length > 0 && `${extraFindings.length} added`,
                manualV !== null && "override active",
              ].filter(Boolean).join(", ")})
            </span>
          )}
        </span>
      </button>

      {showExtra && (
        <div style={{
          border: `1px solid ${GOLD + "40"}`, borderTop: "none",
          borderRadius: "0 0 8px 8px", padding: "18px 18px 14px",
          background: GOLD + "05",
        }}>
          <p style={{ color: TEXT_DIM, fontSize: 13, fontFamily: "Georgia, serif", lineHeight: 1.65, margin: "0 0 16px" }}>
            {hasSurveyResults
              ? "Add threats or vulnerabilities not captured by the survey. These use severity × likelihood weighting (without CVSS) and are included in the confidence interval calculation."
              : "Add your vulnerabilities here. When manually entering vulnerabilities, the breach probability is calculated using a severity × likelihood weighting."}
          </p>

          {extraFindings.length > 0 && (
            <div style={{ marginBottom: 12 }}>
              <SectionLabel>Your vulnerabilities</SectionLabel>
              {extraFindings.map(f => (
                <div key={f.id} style={{ display: "flex", gap: 8, marginBottom: 8, alignItems: "center" }}>
                  <input
                    placeholder="Describe the risk or threat"
                    value={f.name}
                    onChange={e => updateExtra(f.id, "name", e.target.value)}
                    style={{
                      flex: 2, background: CARD, border: `1px solid ${BORDER}`,
                      borderRadius: 7, padding: "8px 12px",
                      color: TEXT_PRI, fontSize: 13, fontFamily: "Georgia, serif",
                    }}
                  />
                  <select value={f.severity} onChange={e => updateExtra(f.id, "severity", e.target.value)} style={selectStyle}>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                  <select value={f.likelihood} onChange={e => updateExtra(f.id, "likelihood", e.target.value)} style={selectStyle}>
                    <option value="high">High likelihood</option>
                    <option value="medium">Medium likelihood</option>
                    <option value="low">Low likelihood</option>
                  </select>
                  <button
                    onClick={() => removeExtra(f.id)}
                    style={{ background: "none", border: "none", color: CRIT + "90", cursor: "pointer", fontSize: 18, padding: "2px 6px" }}
                  >×</button>
                </div>
              ))}
              {extraV > 0 && (
                <div style={{ color: TEXT_MUT, fontSize: 11, fontFamily: "monospace", marginTop: 4, marginBottom: 12 }}>
                  {hasSurveyResults
                    ? `Additional v contribution: +${pct(extraV)} → combined v: ${pct(Math.min(baseV + extraV, 0.95))}`
                    : `v from your entries: ${pct(Math.min(extraV, 0.95))}`}
                </div>
              )}
            </div>
          )}

          <button
            onClick={addExtra}
            style={{
              background: "none", border: `1px dashed ${BORDER}`, borderRadius: 7,
              color: TEXT_DIM, cursor: "pointer", padding: "8px 16px",
              width: "100%", fontSize: 12, fontFamily: "Georgia, serif", marginBottom: 20,
            }}
          >
            + Add {extraFindings.length === 0 ? "a vulnerability" : "another vulnerability"}
          </button>

          {/* Manual override */}
          <div style={{ paddingTop: 16, borderTop: `1px solid ${BORDER}` }}>
            <SectionLabel>Manual vulnerability override</SectionLabel>
            <p style={{ color: TEXT_DIM, fontSize: 12, fontFamily: "Georgia, serif", lineHeight: 1.6, margin: "0 0 12px" }}>
              If you have a breach probability from a penetration test, insurance assessment, or formal risk framework,
              set it here directly. The confidence interval will collapse to a single point when a manual value is active.
            </p>
            <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
              <input
                type="range" min={0} max={0.95} step={0.01}
                value={manualV !== null ? manualV : combinedV}
                onChange={e => setManualV(parseFloat(e.target.value))}
                style={{ flex: 1, accentColor: GOLD, cursor: "pointer" }}
              />
              <span style={{ color: GOLD, fontFamily: "monospace", fontSize: 14, fontWeight: 700, width: 48, textAlign: "right" }}>
                {pct(manualV !== null ? manualV : combinedV)}
              </span>
              {manualV !== null && (
                <button
                  onClick={() => setManualV(null)}
                  style={{
                    background: "none", border: `1px solid ${BORDER}`, borderRadius: 6,
                    color: TEXT_DIM, cursor: "pointer", fontSize: 11,
                    padding: "4px 10px", fontFamily: "Georgia, serif",
                  }}
                >
                  Reset
                </button>
              )}
            </div>
            {manualV !== null && (
              <div style={{ color: HIGH_C, fontSize: 11, fontFamily: "monospace", marginTop: 6 }}>
                ↳ Manual override active: {pct(manualV)}
                {combinedV > 0 && ` (CVSS-computed: ${pct(Math.min(baseV + extraV, 0.95))})`}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Section 3: Asset Value (L) ───────────────────────────────────────────────
function AssetValueSection({ assets, setAssets, surveyAnswers }) {
  const crown    = surveyAnswers?.crown_jewel;
  const hintName = crown && CROWN_JEWEL_HINTS[crown];
  const costCtx  = BREACH_COST_MAP[surveyAnswers?.breach_cost];

  const addRow  = () => setAssets(a => [...a, { id: Date.now(), name: "", value: "" }]);
  const addHint = () => {
    if (!hintName) return;
    setAssets(a =>
      a.some(x => x.name === hintName) ? a
        : [...a.filter(x => x.name), { id: Date.now(), name: hintName, value: "" }]
    );
  };
  const update = (id, field, val) => setAssets(a => a.map(x => x.id === id ? { ...x, [field]: val } : x));
  const remove = (id) => setAssets(a => a.filter(x => x.id !== id));
  const total  = assets.reduce((s, a) => s + (parseFloat(a.value) || 0), 0);

  return (
    <div>
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", marginBottom: 6, flexWrap: "wrap", gap: 8 }}>
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 4 }}>
            <span style={{ color: GOLD, fontFamily: "monospace", fontSize: 10, fontWeight: 700, letterSpacing: "0.1em" }}>L</span>
            <span style={{ color: BORDER2, fontFamily: "monospace", fontSize: 10 }}>·</span>
            <span style={{ color: TEXT_MUT, fontFamily: "monospace", fontSize: 10 }}>Potential Loss — enter your values</span>
          </div>
          <h3 style={{ color: TEXT_PRI, fontFamily: "Georgia, serif", fontSize: 18, fontWeight: 700, margin: 0 }}>
            What is at risk if a breach occurs?
          </h3>
        </div>
        {total > 0 && (
          <div style={{ textAlign: "right" }}>
            <div style={{ color: GOLD, fontSize: 26, fontWeight: 700, fontFamily: "monospace", lineHeight: 1 }}>{fmt(total)}</div>
            <div style={{ color: TEXT_MUT, fontSize: 9, fontFamily: "monospace", marginTop: 2 }}>TOTAL L</div>
          </div>
        )}
      </div>

      <p style={{ color: TEXT_DIM, fontSize: 13, fontFamily: "Georgia, serif", lineHeight: 1.7, margin: "0 0 16px" }}>
        <strong style={{ color: TEXT_SEC }}>L</strong> is the total monetary loss your business would suffer in a breach.
        Gordon &amp; Loeb (2002) stress that underestimating L systematically underestimates how much security investment is warranted.
      </p>

      {costCtx && (
        <div style={{ background: BG, border: `1px solid ${BORDER}`, borderRadius: 8, padding: "12px 16px", marginBottom: 14 }}>
          <div style={{ color: TEXT_MUT, fontSize: 10, fontFamily: "monospace", marginBottom: 5, textTransform: "uppercase", letterSpacing: "0.07em" }}>
            ↳ Context from your survey
          </div>
          <p style={{ color: TEXT_DIM, fontSize: 12, fontFamily: "Georgia, serif", lineHeight: 1.6, margin: 0 }}>{costCtx}</p>
        </div>
      )}

      <div style={{ background: BG, border: `1px solid ${BORDER}`, borderRadius: 8, padding: "14px 18px", marginBottom: 14 }}>
        <SectionLabel>Categories to include in L</SectionLabel>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(230px, 1fr))", gap: "5px 20px" }}>
          {[
            ["IT recovery & forensics",        "$15,000–$100,000 typical for SMEs"],
            ["Customer breach notification",   "$3–$10 per affected individual"],
            ["Legal fees & regulatory fines",  "HIPAA: $100–$50,000 per violation; state laws vary"],
            ["Operational downtime",           "Daily revenue × days offline (avg. 21+ days)"],
            ["Reputational damage",            "Lost contracts, customer churn, brand recovery"],
            ["Direct fraud / ransom losses",   "Wire fraud, ransomware payments — often unrecoverable"],
          ].map(([cat, detail]) => (
            <div key={cat} style={{ display: "flex", gap: 7, marginBottom: 5 }}>
              <span style={{ color: GOLD, fontSize: 10, flexShrink: 0, marginTop: 3 }}>▸</span>
              <div>
                <span style={{ color: TEXT_SEC, fontSize: 12, fontWeight: 700 }}>{cat}</span>
                <span style={{ color: TEXT_MUT, fontSize: 11 }}> — {detail}</span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {hintName && (
        <button
          onClick={addHint}
          style={{
            display: "flex", alignItems: "center", gap: 8,
            background: "transparent", border: `1px dashed ${GOLD}45`,
            borderRadius: 8, color: GOLD, cursor: "pointer",
            padding: "8px 14px", fontSize: 12, fontFamily: "Georgia, serif",
            marginBottom: 10, width: "100%", textAlign: "left",
          }}
        >
          <span>+ Add your primary risk: <em>"{hintName}"</em></span>
        </button>
      )}

      {assets.map(a => (
        <div key={a.id} style={{ display: "flex", gap: 8, marginBottom: 8, alignItems: "center" }}>
          <input
            placeholder="Asset / loss category"
            value={a.name}
            onChange={e => update(a.id, "name", e.target.value)}
            style={{
              flex: 2, background: CARD, border: `1px solid ${BORDER}`,
              borderRadius: 8, padding: "9px 12px",
              color: TEXT_PRI, fontSize: 13, fontFamily: "Georgia, serif",
            }}
          />
          <div style={{ flex: 1, display: "flex", alignItems: "center", position: "relative" }}>
            <span style={{ position: "absolute", left: 10, color: GOLD, fontWeight: 700, fontSize: 13, fontFamily: "monospace" }}>$</span>
            <input
              type="number" placeholder="0" value={a.value}
              onChange={e => update(a.id, "value", e.target.value)}
              style={{
                width: "100%", background: CARD, border: `1px solid ${BORDER}`,
                borderRadius: 8, padding: "9px 10px 9px 24px",
                color: TEXT_PRI, fontSize: 13, fontFamily: "monospace",
              }}
            />
          </div>
          {assets.length > 1 && (
            <button onClick={() => remove(a.id)} style={{ background: "none", border: "none", color: CRIT + "80", cursor: "pointer", fontSize: 18, padding: "2px 6px" }}>×</button>
          )}
        </div>
      ))}
      <button
        onClick={addRow}
        style={{
          background: "none", border: `1px dashed ${BORDER}`, borderRadius: 8,
          color: TEXT_DIM, cursor: "pointer", padding: "8px 16px",
          width: "100%", fontSize: 12, fontFamily: "Georgia, serif", marginTop: 4,
        }}
      >
        + Add category
      </button>

      {total === 0 && (
        <InfoBox color={HIGH_C}>
          Enter at least one asset value to see your full economic analysis. Even a rough estimate is useful — the model is designed to work with imperfect information.
        </InfoBox>
      )}
    </div>
  );
}

// ─── Section 4: Live Results ──────────────────────────────────────────────────
function ResultsSection({ v, vLow, vHigh, L, model, currentSpend, setCurrentSpend, revenue, setRevenue }) {
  const EL    = v * L;
  const ELLow = vLow * L;
  const ELHigh = vHigh * L;
  const cap   = GL_CAP * EL;
  const capLow = GL_CAP * ELLow;
  const capHigh = GL_CAP * ELHigh;
  const spend = parseFloat(currentSpend) || 0;
  const rev   = parseFloat(revenue) || 0;
  const vColor = v > 0.6 ? CRIT : v > 0.3 ? HIGH_C : LOW_C;
  const hasCI = vLow !== v || vHigh !== v;

  const verdict = spend === 0   ? "no-spend"
    : spend < cap * 0.5         ? "severely-under"
    : spend < cap               ? "under"
    : spend > cap               ? "over"
                                : "optimal";

  const verdictCfg = {
    "no-spend":       { color: CRIT,   icon: "⚠", label: "No security spend detected"      },
    "severely-under": { color: CRIT,   icon: "⚠", label: "Significantly under-invested"    },
    "under":          { color: HIGH_C, icon: "↑", label: "Below Gordon–Loeb ceiling"        },
    "over":           { color: MED_C,  icon: "ℹ", label: "Above Gordon–Loeb ceiling"        },
    "optimal":        { color: LOW_C,  icon: "✓", label: "Near optimal range"              },
  };
  const vc = verdictCfg[verdict];

  const tiers = [
    { p: 0.10,  label: "Conservative (10% of EL)", sub: "Address critical findings only",           color: LOW_C  },
    { p: 0.20,  label: "Moderate (20% of EL)",     sub: "Recommended for most SMEs",               color: HIGH_C },
    { p: GL_CAP, label: "GL Maximum (1/e ≈ 37%)",  sub: "Economic ceiling — positive net value below this", color: CRIT   },
  ];

  const mediumCount = (model.findings || []).filter(f => f.severity === "medium").length;

  return (
    <div>
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 16 }}>
        <span style={{ color: GOLD, fontFamily: "monospace", fontSize: 10, fontWeight: 700, letterSpacing: "0.1em" }}>z*</span>
        <span style={{ color: BORDER2, fontFamily: "monospace", fontSize: 10 }}>·</span>
        <span style={{ color: TEXT_MUT, fontFamily: "monospace", fontSize: 10 }}>Economic Analysis — updates live</span>
      </div>

      {/* Key stats */}
      <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginBottom: 18 }}>
        <StatBox
          label="Vulnerability (v)"
          value={v > 0 ? pct(v) : "—"}
          color={v > 0 ? vColor : undefined}
          sub={v > 0 && hasCI ? `± ${(((vHigh - vLow) / 2) * 100).toFixed(1)}%` : v > 0 ? "manual" : "not set"}
        />
        <StatBox label="Potential Loss (L)" value={L > 0 ? fmt(L) : "—"} />
        <StatBox label="Expected Loss (v×L)" value={EL > 0 ? fmt(EL) : "—"} color={EL > 0 ? TEXT_SEC : undefined}
          sub={EL > 0 && hasCI ? `range: ${fmt(ELLow)} – ${fmt(ELHigh)}` : undefined} />
        <StatBox label="GL Investment Cap" value={cap > 0 ? fmt(cap) : "—"} color={cap > 0 ? GOLD : undefined}
          sub={cap > 0 && hasCI ? `range: ${fmt(capLow)} – ${fmt(capHigh)}` : undefined} />
      </div>

      {v === 0 && L === 0 && (
        <InfoBox color={MED_C}>Set your vulnerability (v) above, then enter your asset value (L) to compute your investment ceiling.</InfoBox>
      )}
      {v === 0 && L > 0 && (
        <InfoBox color={HIGH_C}>Asset value entered. Add vulnerabilities or set v above to compute your investment ceiling.</InfoBox>
      )}
      {v > 0 && L === 0 && (
        <InfoBox color={HIGH_C}>Vulnerability set to {pct(v)}. Enter your asset value (L) above to see your full economic analysis.</InfoBox>
      )}

      {L > 0 && v > 0 && (
        <>
          <FormulaBox>
            z* ≤ (1/e) × {pct(v)} × {fmt(L)} = {fmt(cap)}
            {hasCI ? `  |  CI range: ${fmt(capLow)} – ${fmt(capHigh)}` : ""}
            {spend > 0 ? `  |  Current: ${fmt(spend)} (${spend <= cap ? "within cap ✓" : "above cap ⚠"})` : ""}
          </FormulaBox>

          <div style={{ background: BG, border: `1px solid ${BORDER}`, borderRadius: 8, padding: "14px 18px", marginBottom: 18 }}>
            <SectionLabel>Investment scenarios</SectionLabel>
            {tiers.map(t => (
              <div key={t.label} style={{ display: "flex", alignItems: "center", gap: 12, padding: "10px 0", borderBottom: `1px solid ${BORDER}` }}>
                <div style={{ width: 88, flexShrink: 0 }}>
                  <div style={{ height: 5, background: BORDER, borderRadius: 3, overflow: "hidden" }}>
                    <div style={{ width: `${(t.p / GL_CAP) * 100}%`, height: "100%", background: t.color, borderRadius: 3 }} />
                  </div>
                  <div style={{ color: TEXT_MUT, fontSize: 9, fontFamily: "monospace", marginTop: 2 }}>{(t.p * 100).toFixed(0)}% of EL</div>
                </div>
                <div style={{ flex: 1 }}>
                  <div style={{ color: TEXT_SEC, fontSize: 12, fontWeight: 700, fontFamily: "Georgia, serif" }}>{t.label}</div>
                  <div style={{ color: TEXT_MUT, fontSize: 11, fontFamily: "Georgia, serif" }}>{t.sub}</div>
                </div>
                <div style={{ textAlign: "right", flexShrink: 0 }}>
                  <div style={{ color: t.color, fontWeight: 700, fontSize: 15, fontFamily: "monospace" }}>{fmt(t.p * EL)}</div>
                  {hasCI && (
                    <div style={{ color: TEXT_MUT, fontSize: 9, fontFamily: "monospace", marginTop: 1 }}>
                      {fmt(t.p * ELLow)} – {fmt(t.p * ELHigh)}
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>

          <div style={{ background: BG, border: `1px solid ${BORDER}`, borderRadius: 8, padding: "14px 18px", marginBottom: 18 }}>
            <SectionLabel>Key insight — diminishing returns</SectionLabel>
            <p style={{ color: TEXT_DIM, fontSize: 13, fontFamily: "Georgia, serif", lineHeight: 1.65, margin: 0 }}>
              Gordon &amp; Loeb (2002) prove that <strong style={{ color: TEXT_SEC }}>optimal investment does not always increase with vulnerability.</strong>{" "}
              Extremely high-vulnerability systems are often the most expensive to harden — making the per-dollar return on additional security investment
              lower for the most exposed systems than for moderate ones.
              {mediumCount > 0 && (
                <span> Your{" "}
                  <strong style={{ color: MED_C }}>{mediumCount} medium-severity finding{mediumCount !== 1 ? "s" : ""}</strong>{" "}
                  may represent your highest-ROI remediation opportunities.
                </span>
              )}
            </p>
          </div>
        </>
      )}

      {/* Current spend */}
      <div style={{ background: BG, border: `1px solid ${BORDER}`, borderRadius: 8, padding: "16px 18px", marginBottom: cap > 0 ? 18 : 0 }}>
        <SectionLabel>Compare against your current security spend (optional)</SectionLabel>
        <div style={{ display: "flex", gap: 14, flexWrap: "wrap" }}>
          <div style={{ flex: 1, minWidth: 160 }}>
            <div style={{ color: TEXT_MUT, fontSize: 10, fontFamily: "monospace", textTransform: "uppercase", letterSpacing: "0.07em", marginBottom: 6 }}>Annual security budget</div>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <span style={{ color: GOLD, fontFamily: "monospace", fontWeight: 700 }}>$</span>
              <input type="number" placeholder="0" value={currentSpend} onChange={e => setCurrentSpend(e.target.value)}
                style={{ flex: 1, background: CARD, border: `1px solid ${BORDER}`, borderRadius: 7, padding: "9px 12px", color: TEXT_PRI, fontSize: 15, fontFamily: "monospace" }} />
            </div>
          </div>
          <div style={{ flex: 1, minWidth: 160 }}>
            <div style={{ color: TEXT_MUT, fontSize: 10, fontFamily: "monospace", textTransform: "uppercase", letterSpacing: "0.07em", marginBottom: 6 }}>Annual revenue (optional)</div>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <span style={{ color: TEXT_MUT, fontFamily: "monospace", fontWeight: 700 }}>$</span>
              <input type="number" placeholder="0" value={revenue} onChange={e => setRevenue(e.target.value)}
                style={{ flex: 1, background: CARD, border: `1px solid ${BORDER}`, borderRadius: 7, padding: "9px 12px", color: TEXT_PRI, fontSize: 15, fontFamily: "monospace" }} />
            </div>
          </div>
        </div>
      </div>

      {cap > 0 && spend > 0 && (
        <div style={{ background: vc.color + "0d", border: `1px solid ${vc.color}30`, borderLeft: `3px solid ${vc.color}`, borderRadius: 8, padding: "16px 20px" }}>
          <div style={{ color: vc.color, fontSize: 11, fontFamily: "monospace", fontWeight: 700, marginBottom: 6, textTransform: "uppercase", letterSpacing: "0.08em" }}>
            {vc.icon} {vc.label}
          </div>
          <p style={{ color: TEXT_DIM, fontSize: 13, fontFamily: "Georgia, serif", lineHeight: 1.65, margin: 0 }}>
            {verdict === "no-spend"       && `With an expected loss of ${fmt(EL)} and no current security spend, your business absorbs the full weight of this risk uninsured. The Gordon–Loeb model recommends investing up to ${fmt(cap)} annually.`}
            {verdict === "severely-under" && `Your current spend of ${fmt(spend)} is significantly below the GL-recommended range. With ${fmt(cap - spend)} of headroom remaining before the economic ceiling, every additional dollar has a positive expected net return.`}
            {verdict === "under"          && `Your current spend of ${fmt(spend)} is ${fmt(cap - spend)} below the Gordon–Loeb ceiling of ${fmt(cap)}. Increasing investment up to this ceiling is economically justified.`}
            {verdict === "over"           && `Your current spend of ${fmt(spend)} is ${fmt(spend - cap)} above the Gordon–Loeb ceiling of ${fmt(cap)}. Above the ceiling, diminishing returns apply. Consider reallocating excess spend toward higher-ROI controls.`}
            {verdict === "optimal"        && `Your current spend is near the Gordon–Loeb optimal range. Focus on directing existing spend toward the highest-priority findings to maximise risk reduction per dollar.`}
          </p>
          {hasCI && cap > 0 && spend > 0 && (
            <div style={{ color: TEXT_MUT, fontSize: 11, fontFamily: "monospace", marginTop: 8 }}>
              At the confidence interval bounds: GL cap range {fmt(capLow)} – {fmt(capHigh)}.
              {spend < capLow && " Your spend is below even the lower CI bound — investment increase is strongly indicated."}
              {spend > capHigh && " Your spend exceeds even the upper CI bound — diminishing returns apply across all scenarios."}
            </div>
          )}
          {rev > 0 && (
            <div style={{ color: TEXT_MUT, fontSize: 11, fontFamily: "monospace", marginTop: 6 }}>
              Security spend as % of revenue: {((spend / rev) * 100).toFixed(1)}%
              {spend / rev < 0.005 && " — below typical SME benchmark of 0.5–1.5%"}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Section 5: Priority Actions ─────────────────────────────────────────────
function PriorityActions({ findings }) {
  const top = [
    ...findings.filter(f => f.severity === "critical"),
    ...findings.filter(f => f.severity === "high"),
  ].slice(0, 6);

  if (top.length === 0) return null;

  return (
    <div>
      <div style={{ marginBottom: 14 }}>
        <span style={{ color: TEXT_MUT, fontFamily: "monospace", fontSize: 10, textTransform: "uppercase", letterSpacing: "0.1em" }}>
          Priority Actions — highest-impact findings
        </span>
      </div>
      <p style={{ color: TEXT_DIM, fontSize: 13, fontFamily: "Georgia, serif", lineHeight: 1.65, margin: "0 0 16px" }}>
        These findings contribute most to breach probability (v). Each shows its CVSS exploitability profile alongside its v contribution.
      </p>
      {top.map(f => {
        const color = SEV_COLORS[f.severity] || TEXT_MUT;
        const exploit = cvssExploitability(f);
        return (
          <div key={f.id} style={{ background: BG, border: `1px solid ${BORDER}`, borderLeft: `3px solid ${color}`, borderRadius: 8, padding: "14px 18px", marginBottom: 10 }}>
            <div style={{ display: "flex", gap: 10, alignItems: "center", marginBottom: 6, flexWrap: "wrap" }}>
              <SevBadge sev={f.severity} />
              <span style={{ color: TEXT_SEC, fontSize: 13, fontWeight: 700, fontFamily: "Georgia, serif", flex: 1 }}>{f.name}</span>
              <span style={{ color: TEXT_MUT, fontSize: 10, fontFamily: "monospace", flexShrink: 0 }}>
                v: +{pct(findingWeight(f))}
              </span>
            </div>
            {/* CVSS badges */}
            {f.cvss_av && (
              <div style={{ marginBottom: 8 }}>
                <CVSSBadge label="AV" value={f.cvss_av} />
                <CVSSBadge label="AC" value={f.cvss_ac} />
                <CVSSBadge label="PR" value={f.cvss_pr} />
                <CVSSBadge label="UI" value={f.cvss_ui} />
                {exploit !== null && (
                  <span style={{ fontSize: 9, fontFamily: "monospace", color: TEXT_MUT }}>
                    exploit: {(exploit * 100).toFixed(0)}%
                  </span>
                )}
              </div>
            )}
            {f.recommendation && (
              <p style={{ color: TEXT_DIM, fontSize: 13, fontFamily: "Georgia, serif", lineHeight: 1.6, margin: "0 0 8px" }}>{f.recommendation}</p>
            )}
            {f.business_impact && (
              <p style={{ color: TEXT_MUT, fontSize: 12, fontFamily: "Georgia, serif", lineHeight: 1.55, margin: "0 0 8px", fontStyle: "italic" }}>{f.business_impact.slice(0, 160)}…</p>
            )}
            {(f.attack_tactic || f.references?.length > 0) && (
              <div style={{ display: "flex", gap: 14, flexWrap: "wrap" }}>
                {f.attack_tactic && <span style={{ color: TEXT_MUT, fontSize: 10, fontFamily: "monospace" }}>{f.attack_tactic}</span>}
                {f.references?.map(r => (
                  <a key={r} href={r} target="_blank" rel="noreferrer"
                    style={{ color: TEXT_MUT, fontSize: 10, fontFamily: "monospace", textDecoration: "underline", textDecorationColor: BORDER2 }}>
                    {r.trim().replace("https://", "").split("/")[0]}
                  </a>
                ))}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

// ─── Report generator ─────────────────────────────────────────────────────────
function generateReport({ v, vLow, vHigh, L, EL, cap, spend, revenue, model, assets, extraFindings }) {
  const sevColors = { critical: "#e05c5c", high: "#e8a020", medium: "#5b8dd4", low: "#60b06e" };
  const allFindings = [...model.findings, ...extraFindings.filter(f => f.name)];
  const hasSurveyResults = model.summary.total_findings > 0;
  const scoreColor = model.summary.overall_risk_score >= 70 ? "#e05c5c"
    : model.summary.overall_risk_score >= 40 ? "#e8a020" : "#60b06e";
  const hasCI = vLow !== v || vHigh !== v;
  const capLow = GL_CAP * vLow * L;
  const capHigh = GL_CAP * vHigh * L;

  const verdictText = spend === 0
    ? `No security budget detected. Expected loss: ${fmt(EL)}. Recommended investment: up to ${fmt(cap)} annually.`
    : spend < cap
    ? `Current spend of ${fmt(spend)} is ${fmt(cap - spend)} below the GL ceiling. Increasing investment is economically justified.`
    : `Current spend of ${fmt(spend)} is ${fmt(spend - cap)} above the GL ceiling of ${fmt(cap)}. Diminishing returns apply above this threshold.`;

  const findingsHTML = allFindings.map(f => `
    <div style="border-left:4px solid ${sevColors[f.severity]||"#999"};margin-bottom:16px;padding:12px 16px;background:#f9f9f9;border-radius:4px;">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;flex-wrap:wrap;">
        <span style="background:${sevColors[f.severity]}22;border:1px solid ${sevColors[f.severity]}55;color:${sevColors[f.severity]};padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700;text-transform:uppercase;font-family:monospace;">${f.severity}</span>
        <strong style="font-size:14px;font-family:Georgia,serif;">${f.name}</strong>
        <span style="color:#666;font-size:11px;font-family:monospace;margin-left:auto;">v: +${pct(findingWeight(f))}</span>
      </div>
      ${f.cvss_av ? `<div style="margin-bottom:8px;font-family:monospace;font-size:10px;color:#666;">AV:${f.cvss_av.toUpperCase()} AC:${f.cvss_ac.toUpperCase()} PR:${f.cvss_pr.toUpperCase()} UI:${f.cvss_ui.toUpperCase()}</div>` : ""}
      ${f.recommendation ? `<p style="margin:0 0 6px;font-size:13px;line-height:1.6;font-family:Georgia,serif;">${f.recommendation}</p>` : ""}
      ${f.business_impact ? `<p style="margin:0;font-size:12px;color:#666;font-style:italic;font-family:Georgia,serif;">${f.business_impact.slice(0,180)}…</p>` : ""}
    </div>`).join("");

  const assetsHTML = assets.filter(a => a.name).map(a => `
    <tr>
      <td style="padding:8px 12px;border-bottom:1px solid #e2e8f0;">${a.name}</td>
      <td style="padding:8px 12px;border-bottom:1px solid #e2e8f0;text-align:right;font-family:monospace;font-weight:700;">${fmt(parseFloat(a.value)||0)}</td>
    </tr>`).join("");

  const html = `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"/>
<title>MicroSOC — Gordon-Loeb Economic Report</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:Georgia,serif;background:#fff;color:#1a202c;font-size:14px}.page{max-width:820px;margin:0 auto;padding:48px 40px}.header{background:#0b1117;color:#fff;padding:32px 40px;border-radius:10px;margin-bottom:32px}.header h1{font-size:22px;font-weight:800;color:#c8922a;margin-bottom:4px}.header .sub{color:#94a3b8;font-size:13px}h2{font-size:14px;font-weight:700;color:#0b1117;text-transform:uppercase;letter-spacing:.07em;margin:28px 0 12px;border-bottom:2px solid #c8922a;padding-bottom:6px}.stats{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:20px}.stat{background:#f7fafc;border:1px solid #e2e8f0;border-radius:8px;padding:12px 16px;flex:1;min-width:120px}.stat .lbl{font-size:10px;text-transform:uppercase;letter-spacing:.07em;color:#718096;margin-bottom:4px;font-family:monospace}.stat .val{font-size:20px;font-weight:800;font-family:monospace}.stat.gold .val{color:#c8922a}.formula{background:#0b1117;color:#c8922a;padding:12px 18px;border-radius:6px;font-family:monospace;font-size:13px;margin:12px 0;white-space:pre-wrap}.verdict{padding:14px 18px;border-radius:8px;margin:16px 0;border-left:3px solid #c8922a;background:#fffbeb;font-size:13px;line-height:1.65}table{width:100%;border-collapse:collapse;margin:12px 0;font-size:13px}th{background:#0b1117;color:#94a3b8;text-align:left;padding:8px 12px;font-size:10px;text-transform:uppercase;letter-spacing:.07em;font-family:monospace}td{padding:8px 12px}.ci-note{background:#f0f4ff;border-left:3px solid #5b8dd4;padding:10px 14px;margin:10px 0;font-size:12px;color:#4a5568;font-family:monospace}.citation{background:#f7fafc;border-left:3px solid #c8922a;padding:12px 16px;margin:12px 0;font-size:11px;color:#4a5568;font-style:italic;line-height:1.7}.footer{margin-top:48px;padding-top:16px;border-top:1px solid #e2e8f0;color:#718096;font-size:10px;text-align:center;font-family:monospace}</style>
</head><body><div class="page">
<div class="header"><h1>MicroSOC — Gordon-Loeb Economic Report</h1>
<div class="sub">Cybersecurity Investment Analysis · CVSS v3.1 + Gordon-Loeb (2002) · PASTA + MITRE ATT&amp;CK</div>
<div class="sub" style="margin-top:4px;font-family:monospace;font-size:11px;color:#4a5568;">Generated: ${new Date().toLocaleDateString("en-US",{year:"numeric",month:"long",day:"numeric"})}</div></div>
<h2>Executive Summary</h2>
<div class="stats">
  ${hasSurveyResults ? `<div class="stat"><div class="lbl">Risk Score</div><div class="val" style="color:${scoreColor}">${model.summary.overall_risk_score}/100</div></div>` : ""}
  <div class="stat"><div class="lbl">Total Findings</div><div class="val">${allFindings.length}</div></div>
  <div class="stat"><div class="lbl">Vulnerability (v)</div><div class="val">${pct(v)}</div></div>
  <div class="stat"><div class="lbl">Expected Loss (v×L)</div><div class="val">${fmt(EL)}</div></div>
  <div class="stat gold"><div class="lbl">GL Investment Cap</div><div class="val">${fmt(cap)}</div></div>
  ${spend > 0 ? `<div class="stat"><div class="lbl">Current Spend</div><div class="val">${fmt(spend)}</div></div>` : ""}
</div>
${hasCI ? `<div class="ci-note">Confidence interval (severity ±1 grade): v ${pct(vLow)} – ${pct(vHigh)} · EL ${fmt(vLow*L)} – ${fmt(vHigh*L)} · GL cap ${fmt(capLow)} – ${fmt(capHigh)}</div>` : ""}
<div class="formula">z* ≤ (1/e) × v × L = 0.3679 × ${pct(v)} × ${fmt(L)} = ${fmt(cap)}${hasCI ? `\nCI range: ${fmt(capLow)} – ${fmt(capHigh)}` : ""}</div>
<div class="verdict">${verdictText}</div>
${parseFloat(revenue) > 0 ? `<p style="font-size:12px;color:#718096;margin-top:8px;font-family:monospace;">Security spend as % of revenue: ${((spend/parseFloat(revenue))*100).toFixed(1)}%</p>` : ""}
<h2>Findings (${allFindings.length}${extraFindings.filter(f=>f.name).length > 0 ? `, including ${extraFindings.filter(f=>f.name).length} manual` : ""})</h2>
${allFindings.length > 0 ? findingsHTML : "<p style='color:#718096;font-size:13px;'>No findings entered.</p>"}
<h2>Asset Inventory (L = ${fmt(L)})</h2>
<table><tr><th>Asset / Loss Category</th><th style="text-align:right">Estimated Value</th></tr>
${assetsHTML}
<tr><td style="font-weight:700;padding:8px 12px;">Total (L)</td><td style="text-align:right;font-weight:800;color:#c8922a;font-family:monospace;padding:8px 12px;">${fmt(L)}</td></tr></table>
<h2>Investment Scenarios</h2>
<table><tr><th>Scenario</th><th style="text-align:right">Amount</th>${hasCI ? "<th style='text-align:right'>CI Range</th>" : ""}<th>Notes</th></tr>
<tr><td style="padding:8px 12px;">Conservative (10%)</td><td style="text-align:right;padding:8px 12px;font-family:monospace;">${fmt(0.10*EL)}</td>${hasCI ? `<td style="text-align:right;padding:8px 12px;font-family:monospace;font-size:11px;color:#718096;">${fmt(0.10*vLow*L)} – ${fmt(0.10*vHigh*L)}</td>` : ""}<td style="padding:8px 12px;">Critical findings only</td></tr>
<tr style="background:#f7fafc"><td style="padding:8px 12px;">Moderate (20%)</td><td style="text-align:right;padding:8px 12px;font-family:monospace;">${fmt(0.20*EL)}</td>${hasCI ? `<td style="text-align:right;padding:8px 12px;font-family:monospace;font-size:11px;color:#718096;">${fmt(0.20*vLow*L)} – ${fmt(0.20*vHigh*L)}</td>` : ""}<td style="padding:8px 12px;">Recommended for most SMEs</td></tr>
<tr><td style="padding:8px 12px;font-weight:700;">GL Maximum (37%)</td><td style="text-align:right;padding:8px 12px;font-family:monospace;font-weight:700;color:#c8922a;">${fmt(cap)}</td>${hasCI ? `<td style="text-align:right;padding:8px 12px;font-family:monospace;font-size:11px;color:#718096;">${fmt(capLow)} – ${fmt(capHigh)}</td>` : ""}<td style="padding:8px 12px;">Economic upper bound</td></tr>
${spend > 0 ? `<tr style="background:#f7fafc"><td style="padding:8px 12px;">Your current spend</td><td style="text-align:right;padding:8px 12px;font-family:monospace;">${fmt(spend)}</td>${hasCI ? "<td></td>" : ""}<td style="padding:8px 12px;">${spend > cap ? "Above GL cap" : "Within GL range"}</td></tr>` : ""}
</table>
<h2>Citations</h2>
<div class="citation">
Gordon, L. A., &amp; Loeb, M. P. (2002). The Economics of Information Security Investment. <em>ACM Transactions on Information and System Security, 5</em>(4), 438–457.<br/><br/>
NIST. (2019). Common Vulnerability Scoring System v3.1: Specification Document. FIRST.org. https://www.first.org/cvss/specification-document<br/><br/>
Gordon, L. A., et al. (2020). Integrating cost–benefit analysis into the NIST Cybersecurity Framework via the Gordon–Loeb Model. <em>Journal of Cybersecurity, 6</em>(1), tyaa005.
</div>
<div class="footer">MicroSOC · CVSS v3.1 + Gordon-Loeb Economic Module · ${new Date().toISOString().slice(0,10)}</div>
</div></body></html>`;

  const blob = new Blob([html], { type: "text/html" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `MicroSOC_EconomicReport_${new Date().toISOString().slice(0,10)}.html`;
  a.click();
  URL.revokeObjectURL(url);
}

// ─── Main export ──────────────────────────────────────────────────────────────
export default function GordonLoebWalkthrough({ threatModel, surveyAnswers, onBack }) {
  const model = threatModel ?? EMPTY_MODEL;
  const hasSurveyResults = model.summary.total_findings > 0;

  const [assets,        setAssets]        = useState([{ id: 1, name: "", value: "" }]);
  const [extraFindings, setExtraFindings] = useState([]);
  const [manualV,       setManualV]       = useState(null);
  const [currentSpend,  setCurrentSpend]  = useState("");
  const [revenue,       setRevenue]       = useState("");

  const validExtra = extraFindings.filter(f => f.name);
  const allFindings = useMemo(() => [...model.findings, ...validExtra], [model.findings, validExtra]);

  // Central v
  const v = useMemo(() => {
    if (manualV !== null) return manualV;
    return Math.min(computeV(model.findings) + computeV(validExtra), 0.95);
  }, [model.findings, validExtra, manualV]);

  // CI bounds
  const { low: vLow, high: vHigh } = useMemo(() => {
    if (manualV !== null) return { low: manualV, high: manualV };
    return computeVBounds(allFindings);
  }, [allFindings, manualV]);

  const L   = useMemo(() => assets.reduce((s, a) => s + (parseFloat(a.value) || 0), 0), [assets]);
  const EL  = v * L;
  const cap = GL_CAP * EL;

  return (
    <div style={{
      minHeight: "100vh", background: BG,
      backgroundImage: `
        radial-gradient(ellipse 60% 50% at 15% 0%,   rgba(200,146,42,0.04) 0%, transparent 60%),
        radial-gradient(ellipse 50% 40% at 85% 100%, rgba(91,141,212,0.04) 0%, transparent 60%)
      `,
      fontFamily: "Georgia, serif", padding: "48px 20px 100px",
    }}>
      <div style={{ maxWidth: 1100, margin: "0 auto" }}>

        {/* Page header */}
        <div style={{ marginBottom: 40 }}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 22 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <div style={{ width: 8, height: 8, borderRadius: "50%", background: GOLD, boxShadow: `0 0 10px ${GOLD}88` }} />
              <span style={{ color: TEXT_MUT, fontSize: 11, fontFamily: "monospace", letterSpacing: "0.16em", textTransform: "uppercase" }}>
                MicroSOC · Economic Analysis
              </span>
            </div>
            <button onClick={onBack} style={{ background: "none", border: `1px solid ${BORDER}`, borderRadius: 6, color: TEXT_DIM, cursor: "pointer", fontSize: 12, padding: "5px 14px", fontFamily: "Georgia, serif" }}>
              {hasSurveyResults ? "← Back to home (download your report first!)" : "← Home"}
            </button>
          </div>
          <h1 style={{ fontSize: 36, color: TEXT_PRI, margin: "0 0 6px", lineHeight: 1.1, fontWeight: 700, letterSpacing: "-0.5px" }}>
            Gordon–Loeb Investment Model
          </h1>
          <p style={{ color: TEXT_DIM, fontSize: 15, margin: 0, lineHeight: 1.7, maxWidth: 600 }}>
            {hasSurveyResults
              ? <>Your <strong style={{ color: TEXT_SEC }}>{model.summary.total_findings} confirmed findings</strong> drive this analysis via <strong style={{ color: TEXT_SEC }}>CVSS v3.1 exploitability scoring</strong>, producing a breach probability with a confidence interval. Enter your asset value to compute your investment ceiling.</>
              : <>Enter your vulnerabilities and asset value to compute your optimal cybersecurity investment ceiling using the Gordon–Loeb model.</>
            }
          </p>
        </div>

        {/* Main card */}
        <div style={{ background: CARD, border: `1px solid ${BORDER}`, borderRadius: 16, padding: "36px 44px", boxShadow: "0 8px 60px rgba(0,0,0,0.5), inset 0 1px 0 rgba(255,255,255,0.03)" }}>

          <GLIntro model={model} />
          <Divider />

          <VulnerabilitySection
            model={model}
            extraFindings={extraFindings}
            setExtraFindings={setExtraFindings}
            manualV={manualV}
            setManualV={setManualV}
          />
          <Divider />

          <AssetValueSection assets={assets} setAssets={setAssets} surveyAnswers={surveyAnswers} />
          <Divider />

          <ResultsSection
            v={v} vLow={vLow} vHigh={vHigh}
            L={L} model={model}
            currentSpend={currentSpend} setCurrentSpend={setCurrentSpend}
            revenue={revenue} setRevenue={setRevenue}
          />

          {allFindings.length > 0 && L > 0 && (
            <>
              <Divider />
              <PriorityActions findings={allFindings} />
            </>
          )}

          <Divider />

          {/* Citations */}
          <div style={{ background: BG, border: `1px solid ${BORDER}`, borderRadius: 8, padding: "14px 18px" }}>
            <SectionLabel>Citations</SectionLabel>
            <p style={{ color: TEXT_MUT, fontSize: 11, fontFamily: "Georgia, serif", lineHeight: 1.8, margin: 0, fontStyle: "italic" }}>
              Gordon, L. A., &amp; Loeb, M. P. (2002). The Economics of Information Security Investment.{" "}
              <em>ACM Transactions on Information and System Security, 5</em>(4), 438–457.<br />
              NIST. (2019). Common Vulnerability Scoring System v3.1: Specification Document. FIRST.org.<br />
              Gordon, L. A., et al. (2020). Integrating cost–benefit analysis into the NIST Cybersecurity Framework via the Gordon–Loeb Model.{" "}
              <em>Journal of Cybersecurity, 6</em>(1), tyaa005.
            </p>
          </div>

          {/* Download */}
          <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 28, paddingTop: 24, borderTop: `1px solid ${BORDER}` }}>
            <button
              onClick={() => generateReport({ v, vLow, vHigh, L, EL, cap, spend: parseFloat(currentSpend)||0, revenue, model, assets, extraFindings })}
              disabled={L === 0}
              style={{
                padding: "12px 28px", borderRadius: 8, border: "none",
                background: L > 0 ? GOLD : BORDER, color: L > 0 ? "#0b1117" : TEXT_MUT,
                cursor: L > 0 ? "pointer" : "not-allowed", fontSize: 14, fontWeight: 700,
                fontFamily: "Georgia, serif", boxShadow: L > 0 ? `0 2px 16px ${GOLD}44` : "none",
                transition: "all 0.2s",
              }}
            >
              {L > 0 ? "↓ Download Full Report" : "Enter an asset value to download"}
            </button>
          </div>
        </div>

        <p style={{ textAlign: "center", color: TEXT_MUT, fontSize: 11, marginTop: 20, fontFamily: "monospace" }}>
          All responses processed locally · No data transmitted externally
        </p>
      </div>
    </div>
  );
}
