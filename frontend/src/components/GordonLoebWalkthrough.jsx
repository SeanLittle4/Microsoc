import { useState, useMemo } from "react";

// ─── Design tokens — exact match with Survey.jsx ──────────────────────────────
const BG       = "#0b1117";
const CARD     = "#0e1822";
const BORDER   = "#141e28";
const BORDER2  = "#1e2e3e";
const GOLD     = "#c8922a";
const TEXT_PRI = "#e8ddd0";
const TEXT_SEC = "#8a9eb0";
const TEXT_DIM = "#3a5568";
const TEXT_MUT = "#2e4458";
const CRIT     = "#e05c5c";
const HIGH_C   = "#e8a020";
const MED_C    = "#5b8dd4";
const LOW_C    = "#60b06e";
const SEV_COLORS = { critical: CRIT, high: HIGH_C, medium: MED_C, low: LOW_C };

// ─── Gordon-Loeb constants ────────────────────────────────────────────────────
const GL_CAP = 1 / Math.E; // ≈ 0.3679 — the 37% upper bound

// Severity × likelihood → vulnerability contribution weight
// Each confirmed finding shifts v upward proportional to exploitability.
// Weights calibrated to Gordon & Loeb (2002): v = breach probability
// under current controls, capped at 0.95.
const SEV_W  = { critical: 0.18, high: 0.10, medium: 0.05, low: 0.02 };
const LIKE_M = { high: 1.0,      medium: 0.75,             low: 0.5  };

// ─── Helpers ──────────────────────────────────────────────────────────────────
const fmt = (n) =>
  Number.isFinite(n)
    ? n.toLocaleString("en-US", { style: "currency", currency: "USD", maximumFractionDigits: 0 })
    : "—";

const pct = (n) => (Number.isFinite(n) ? `${(n * 100).toFixed(1)}%` : "—");

function computeV(findings) {
  const raw = findings.reduce(
    (sum, f) => sum + (SEV_W[f.severity] || 0) * (LIKE_M[f.likelihood] || 0.5),
    0
  );
  return Math.min(raw, 0.95);
}

function findingWeight(f) {
  return (SEV_W[f.severity] || 0) * (LIKE_M[f.likelihood] || 0.5);
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

const StatBox = ({ label, value, color, sub }) => (
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

// ─── Section 1: GL Introduction ───────────────────────────────────────────────
function GLIntro({ threatModel }) {
  const [open, setOpen] = useState(false);
  const { summary } = threatModel;
  const scoreColor = summary.overall_risk_score >= 70 ? CRIT
    : summary.overall_risk_score >= 40 ? HIGH_C : LOW_C;

  return (
    <div>
      {/* Threat model summary — always visible */}
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
            <strong style={{ color: GOLD }}>Gordon–Loeb Model</strong>. Enter your asset value below to see your complete investment picture — everything else is computed automatically.
          </p>
        </div>
      </div>

      {/* Collapsible model explanation */}
      <button
        onMouseDown={e => e.preventDefault()}
        onClick={() => setOpen(o => !o)}
        style={{
          display: "flex", alignItems: "center", gap: 10, width: "100%",
          background: "none", border: `1px solid ${BORDER}`, borderRadius: 8,
          padding: "10px 16px", cursor: "pointer", textAlign: "left", userSelect: "none",
        }}
      >
        <span style={{ color: TEXT_MUT, fontSize: 10, fontFamily: "monospace", textTransform: "uppercase", letterSpacing: "0.08em", flex: 1 }}>
          About the Gordon–Loeb Model (2002)
        </span>
        <span style={{ color: TEXT_MUT, fontSize: 12 }}>{open ? "▲" : "▼"}</span>
      </button>

      {open && (
        <div style={{ background: BG, border: `1px solid ${BORDER}`, borderTop: "none", borderRadius: "0 0 8px 8px", padding: "18px" }}>
          <p style={{ color: TEXT_DIM, fontSize: 13, fontFamily: "Georgia, serif", lineHeight: 1.7, margin: "0 0 12px" }}>
            Published in <em>ACM Transactions on Information and System Security</em> (2002) by Lawrence A. Gordon and Martin P. Loeb of the University of Maryland, this model is widely regarded as the "gold standard" for determining how much an organization should invest in cybersecurity. It has been cited in the NIST Cybersecurity Framework, the U.S. Council of Better Business Bureaus SMB cybersecurity guide, and covered by the <em>Wall Street Journal</em> and <em>Financial Times</em>.
          </p>
          <p style={{ color: TEXT_DIM, fontSize: 13, fontFamily: "Georgia, serif", lineHeight: 1.7, margin: "0 0 12px" }}>
            The core theorem proves that for all realistic security breach probability functions, the economically rational investment ceiling is <strong style={{ color: GOLD }}>1/e ≈ 36.8%</strong> of your expected loss. Beyond this threshold, each additional dollar spent on security returns less risk reduction than its cost — producing negative net value. Below it, every dollar has a positive expected return.
          </p>
          <FormulaBox>z* ≤ (1/e) × v × L &nbsp;&nbsp;≈&nbsp;&nbsp; 0.3679 × v × L</FormulaBox>
          <div style={{ display: "flex", flexDirection: "column", gap: 10, marginTop: 14 }}>
            {[
              { sym: "v", name: "Vulnerability", desc: "Probability of a breach given your current controls. MicroSOC derives this directly from your confirmed findings — you never estimate it manually." },
              { sym: "L", name: "Potential Loss",   desc: "Total monetary loss if a breach occurs — IT recovery, legal fees, downtime, notification, regulatory fines, and reputational damage combined." },
              { sym: "z*", name: "Optimal Investment", desc: "The maximum you should invest annually. Spending more than this ceiling yields diminishing returns. Spending less leaves exploitable risk on the table." },
            ].map(({ sym, name, desc }) => (
              <div key={sym} style={{ display: "flex", gap: 12, alignItems: "flex-start" }}>
                <div style={{
                  flexShrink: 0, width: 30, height: 30, borderRadius: 6,
                  background: CARD, border: `1px solid ${GOLD}40`,
                  display: "flex", alignItems: "center", justifyContent: "center",
                  fontFamily: "monospace", color: GOLD, fontWeight: 700, fontSize: 12,
                }}>{sym}</div>
                <div>
                  <span style={{ color: TEXT_SEC, fontWeight: 700, fontSize: 13 }}>{name}</span>
                  <span style={{ color: TEXT_DIM, fontSize: 13 }}> — {desc}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Section 2: Vulnerability (v) ────────────────────────────────────────────
function VulnerabilitySection({ threatModel, extraFindings, setExtraFindings, manualV, setManualV }) {
  const [showExtra, setShowExtra] = useState(false);

  const baseV     = computeV(threatModel.findings);
  const extraV    = computeV(extraFindings.filter(f => f.name));
  const combinedV = manualV !== null ? manualV : Math.min(baseV + extraV, 0.95);
  const vColor    = combinedV > 0.6 ? CRIT : combinedV > 0.3 ? HIGH_C : LOW_C;

  const addExtra = () =>
    setExtraFindings(f => [...f, { id: `extra-${Date.now()}`, name: "", severity: "high", likelihood: "medium" }]);

  const updateExtra = (id, field, val) =>
    setExtraFindings(f => f.map(x => x.id === id ? { ...x, [field]: val } : x));

  const removeExtra = (id) =>
    setExtraFindings(f => f.filter(x => x.id !== id));

  const hasExtras = extraFindings.length > 0 || manualV !== null;

  const selectStyle = {
    background: CARD, border: `1px solid ${BORDER}`, borderRadius: 6,
    color: TEXT_SEC, fontSize: 12, fontFamily: "monospace", padding: "6px 8px", cursor: "pointer",
  };

  return (
    <div>
      {/* Header row with live v value */}
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", marginBottom: 14, flexWrap: "wrap", gap: 10 }}>
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 4 }}>
            <span style={{ color: GOLD, fontFamily: "monospace", fontSize: 10, fontWeight: 700, letterSpacing: "0.1em" }}>v</span>
            <span style={{ color: BORDER2, fontFamily: "monospace", fontSize: 10 }}>·</span>
            <span style={{ color: TEXT_MUT, fontFamily: "monospace", fontSize: 10 }}>Vulnerability — auto-computed from findings</span>
          </div>
          <h3 style={{ color: TEXT_PRI, fontFamily: "Georgia, serif", fontSize: 18, fontWeight: 700, margin: 0, lineHeight: 1.2 }}>
            Breach Probability
          </h3>
        </div>
        <div style={{ fontSize: 34, fontWeight: 700, color: vColor, fontFamily: "monospace", lineHeight: 1 }}>
          {pct(combinedV)}
        </div>
      </div>

      {/* Progress bar */}
      <div style={{ height: 7, background: BORDER, borderRadius: 4, overflow: "hidden", marginBottom: 10 }}>
        <div style={{ width: `${combinedV * 100}%`, height: "100%", background: vColor, borderRadius: 4, transition: "width 0.5s" }} />
      </div>
      <p style={{ color: TEXT_DIM, fontSize: 13, fontFamily: "Georgia, serif", lineHeight: 1.65, margin: "0 0 16px" }}>
        {combinedV > 0.6
          ? "High breach probability. Multiple confirmed threat vectors create compounding risk across your environment. This is the most common profile for SMEs that have not yet implemented baseline controls."
          : combinedV > 0.3
          ? "Moderate breach probability. Gordon & Loeb (2002) note that moderate-vulnerability organizations often derive the highest return on security investment — because the most impactful controls are still available and addressable."
          : "Lower breach probability. Security investment still creates positive expected value — the recommended ceiling will be proportionally smaller, but targeted controls remain worthwhile."}
      </p>

      {/* Finding breakdown table */}
      <div style={{ background: BG, border: `1px solid ${BORDER}`, borderRadius: 8, padding: "14px 18px", marginBottom: 14 }}>
        <SectionLabel>
          {threatModel.findings.length} confirmed finding{threatModel.findings.length !== 1 ? "s" : ""} from your assessment
        </SectionLabel>
        {threatModel.findings.map((f, i) => {
          const w = findingWeight(f);
          const color = SEV_COLORS[f.severity] || TEXT_MUT;
          const barW = Math.min((w / 0.18) * 100, 100);
          return (
            <div key={f.id} style={{
              display: "flex", alignItems: "center", gap: 10, padding: "9px 0",
              borderBottom: i < threatModel.findings.length - 1 ? `1px solid ${BORDER}` : "none",
            }}>
              <SevBadge sev={f.severity} />
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ color: TEXT_SEC, fontSize: 12, fontFamily: "Georgia, serif", fontWeight: 700, lineHeight: 1.3 }}>
                  {f.name}
                </div>
                <div style={{ color: TEXT_MUT, fontSize: 10, fontFamily: "monospace", marginTop: 2 }}>
                  likelihood: {f.likelihood}
                </div>
              </div>
              <div style={{ flexShrink: 0, textAlign: "right", minWidth: 90 }}>
                <div style={{ height: 4, width: 80, background: BORDER, borderRadius: 2, overflow: "hidden", marginBottom: 3 }}>
                  <div style={{ width: `${barW}%`, height: "100%", background: color, borderRadius: 2 }} />
                </div>
                <div style={{ color: color, fontSize: 10, fontFamily: "monospace", fontWeight: 700 }}>+{pct(w)}</div>
              </div>
            </div>
          );
        })}
        <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 10, paddingTop: 8, borderTop: `1px solid ${BORDER}` }}>
          <span style={{ color: TEXT_MUT, fontSize: 11, fontFamily: "monospace", marginRight: 10 }}>Base v from findings:</span>
          <span style={{ color: vColor, fontSize: 13, fontFamily: "monospace", fontWeight: 700 }}>{pct(baseV)}</span>
        </div>
      </div>

      {/* Toggle: additional risk factors */}
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
          {showExtra ? "▼" : "▸"}&nbsp;&nbsp;Additional Risk Factors &amp; Manual Override
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
            Add threats or vulnerabilities not captured by the survey — such as risks specific to your industry, gaps your team has already identified, or findings from a prior security audit or penetration test. Each addition contributes to your computed breach probability using the same severity × likelihood weighting as the threat model.
          </p>

          {/* Extra finding rows */}
          {extraFindings.length > 0 && (
            <div style={{ marginBottom: 12 }}>
              <SectionLabel>Additional risk factors</SectionLabel>
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
                  Additional v contribution: +{pct(extraV)} → combined v: {pct(Math.min(baseV + extraV, 0.95))}
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
            + Add risk factor
          </button>

          {/* Manual override */}
          <div style={{ paddingTop: 16, borderTop: `1px solid ${BORDER}` }}>
            <SectionLabel>Manual vulnerability override (advanced)</SectionLabel>
            <p style={{ color: TEXT_DIM, fontSize: 12, fontFamily: "Georgia, serif", lineHeight: 1.6, margin: "0 0 12px" }}>
              If you have a specific breach probability from a prior penetration test, insurance carrier assessment, or formal risk framework, enter it here to override the computed value entirely. Leave at the auto-computed position to use the finding-derived score.
            </p>
            <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
              <input
                type="range" min={0} max={0.95} step={0.01}
                value={manualV !== null ? manualV : Math.min(baseV + extraV, 0.95)}
                onChange={e => setManualV(parseFloat(e.target.value))}
                style={{ flex: 1, accentColor: GOLD, cursor: "pointer" }}
              />
              <span style={{ color: GOLD, fontFamily: "monospace", fontSize: 14, fontWeight: 700, width: 48, textAlign: "right" }}>
                {pct(manualV !== null ? manualV : Math.min(baseV + extraV, 0.95))}
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
                ↳ Manual override active: {pct(manualV)} (computed: {pct(Math.min(baseV + extraV, 0.95))})
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

  const addRow = () => setAssets(a => [...a, { id: Date.now(), name: "", value: "" }]);

  const addHint = () => {
    if (!hintName) return;
    setAssets(a =>
      a.some(x => x.name === hintName)
        ? a
        : [...a.filter(x => x.name), { id: Date.now(), name: hintName, value: "" }]
    );
  };

  const update = (id, field, val) =>
    setAssets(a => a.map(x => x.id === id ? { ...x, [field]: val } : x));

  const remove = (id) =>
    setAssets(a => a.filter(x => x.id !== id));

  const total = assets.reduce((s, a) => s + (parseFloat(a.value) || 0), 0);

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
        <strong style={{ color: TEXT_SEC }}>L</strong> is the total monetary loss your business would suffer in a breach — not just what you can afford to lose, but what a breach would actually cost. This includes direct losses, recovery costs, and downstream consequences. Gordon &amp; Loeb (2002) stress that underestimating L systematically underestimates how much security investment is warranted.
      </p>

      {/* Survey context */}
      {costCtx && (
        <div style={{ background: BG, border: `1px solid ${BORDER}`, borderRadius: 8, padding: "12px 16px", marginBottom: 14 }}>
          <div style={{ color: TEXT_MUT, fontSize: 10, fontFamily: "monospace", marginBottom: 5, textTransform: "uppercase", letterSpacing: "0.07em" }}>
            ↳ Context from your survey
          </div>
          <p style={{ color: TEXT_DIM, fontSize: 12, fontFamily: "Georgia, serif", lineHeight: 1.6, margin: 0 }}>{costCtx}</p>
        </div>
      )}

      {/* Loss categories */}
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

      {/* Crown jewel hint */}
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

      {/* Asset input rows */}
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
              type="number"
              placeholder="0"
              value={a.value}
              onChange={e => update(a.id, "value", e.target.value)}
              style={{
                width: "100%", background: CARD, border: `1px solid ${BORDER}`,
                borderRadius: 8, padding: "9px 10px 9px 24px",
                color: TEXT_PRI, fontSize: 13, fontFamily: "monospace",
              }}
            />
          </div>
          {assets.length > 1 && (
            <button
              onClick={() => remove(a.id)}
              style={{ background: "none", border: "none", color: CRIT + "80", cursor: "pointer", fontSize: 18, padding: "2px 6px" }}
            >×</button>
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
          Enter at least one asset value to see your full economic analysis. Even a rough estimate is useful — the model is designed to work with imperfect information and still produce meaningful guidance.
        </InfoBox>
      )}
    </div>
  );
}

// ─── Section 4: Live Results ──────────────────────────────────────────────────
function ResultsSection({ v, L, threatModel, currentSpend, setCurrentSpend, revenue, setRevenue }) {
  const EL    = v * L;
  const cap   = GL_CAP * EL;
  const spend = parseFloat(currentSpend) || 0;
  const rev   = parseFloat(revenue) || 0;
  const vColor = v > 0.6 ? CRIT : v > 0.3 ? HIGH_C : LOW_C;

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
    { p: 0.10,  label: "Conservative (10% of EL)", sub: "Address critical findings only — minimum viable security posture",           color: LOW_C  },
    { p: 0.20,  label: "Moderate (20% of EL)",     sub: "Recommended for most SMEs — covers critical and high-severity findings",     color: HIGH_C },
    { p: GL_CAP, label: "GL Maximum (1/e ≈ 37%)",  sub: "Economic ceiling — every dollar below this has positive expected net value", color: CRIT   },
  ];

  return (
    <div>
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 16 }}>
        <span style={{ color: GOLD, fontFamily: "monospace", fontSize: 10, fontWeight: 700, letterSpacing: "0.1em" }}>z*</span>
        <span style={{ color: BORDER2, fontFamily: "monospace", fontSize: 10 }}>·</span>
        <span style={{ color: TEXT_MUT, fontFamily: "monospace", fontSize: 10 }}>Economic Analysis — updates live as you enter values</span>
      </div>

      {/* Key stats */}
      <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginBottom: 18 }}>
        <StatBox label="Vulnerability (v)" value={pct(v)} color={vColor}
          sub={v > 0.6 ? "High risk" : v > 0.3 ? "Moderate risk" : "Lower risk"} />
        <StatBox label="Potential Loss (L)" value={L > 0 ? fmt(L) : "—"} />
        <StatBox label="Expected Loss (v×L)" value={EL > 0 ? fmt(EL) : "—"} color={EL > 0 ? TEXT_SEC : undefined} />
        <StatBox label="GL Investment Cap" value={cap > 0 ? fmt(cap) : "—"} color={cap > 0 ? GOLD : undefined} />
      </div>

      {L > 0 && (
        <>
          <FormulaBox>
            z* ≤ (1/e) × {pct(v)} × {fmt(L)} = {fmt(cap)}
            {spend > 0 ? `  |  Current: ${fmt(spend)} (${spend <= cap ? "within cap ✓" : "above cap ⚠"})` : ""}
          </FormulaBox>

          {/* Investment tiers */}
          <div style={{ background: BG, border: `1px solid ${BORDER}`, borderRadius: 8, padding: "14px 18px", marginBottom: 18 }}>
            <SectionLabel>Investment scenarios</SectionLabel>
            {tiers.map(t => (
              <div key={t.label} style={{
                display: "flex", alignItems: "center", gap: 12,
                padding: "10px 0", borderBottom: `1px solid ${BORDER}`,
              }}>
                <div style={{ width: 88, flexShrink: 0 }}>
                  <div style={{ height: 5, background: BORDER, borderRadius: 3, overflow: "hidden" }}>
                    <div style={{ width: `${(t.p / GL_CAP) * 100}%`, height: "100%", background: t.color, borderRadius: 3 }} />
                  </div>
                  <div style={{ color: TEXT_MUT, fontSize: 9, fontFamily: "monospace", marginTop: 2 }}>
                    {(t.p * 100).toFixed(0)}% of EL
                  </div>
                </div>
                <div style={{ flex: 1 }}>
                  <div style={{ color: TEXT_SEC, fontSize: 12, fontWeight: 700, fontFamily: "Georgia, serif" }}>{t.label}</div>
                  <div style={{ color: TEXT_MUT, fontSize: 11, fontFamily: "Georgia, serif" }}>{t.sub}</div>
                </div>
                <div style={{ color: t.color, fontWeight: 700, fontSize: 15, fontFamily: "monospace", flexShrink: 0 }}>
                  {fmt(t.p * EL)}
                </div>
              </div>
            ))}
          </div>

          {/* Counter-intuitive GL insight */}
          <div style={{ background: BG, border: `1px solid ${BORDER}`, borderRadius: 8, padding: "14px 18px", marginBottom: 18 }}>
            <SectionLabel>Key insight — diminishing returns and moderate vulnerability</SectionLabel>
            <p style={{ color: TEXT_DIM, fontSize: 13, fontFamily: "Georgia, serif", lineHeight: 1.65, margin: 0 }}>
              Gordon &amp; Loeb (2002) prove a counter-intuitive result:{" "}
              <strong style={{ color: TEXT_SEC }}>the optimal investment does not always increase with vulnerability.</strong>{" "}
              Extremely high-vulnerability systems are often the most expensive to harden — making the per-dollar return on additional security investment lower for the most exposed systems than for moderate ones.
              {threatModel.findings.filter(f => f.severity === "medium").length > 0 && (
                <span> Your {" "}
                  <strong style={{ color: MED_C }}>
                    {threatModel.findings.filter(f => f.severity === "medium").length} medium-severity finding{threatModel.findings.filter(f => f.severity === "medium").length !== 1 ? "s" : ""}
                  </strong>{" "}
                  may represent your highest-ROI remediation opportunities — addressable with targeted, lower-cost controls.
                </span>
              )}
            </p>
          </div>
        </>
      )}

      {/* Current spend inputs */}
      <div style={{ background: BG, border: `1px solid ${BORDER}`, borderRadius: 8, padding: "16px 18px", marginBottom: cap > 0 ? 18 : 0 }}>
        <SectionLabel>Compare against your current security spend (optional)</SectionLabel>
        <p style={{ color: TEXT_DIM, fontSize: 12, fontFamily: "Georgia, serif", lineHeight: 1.6, margin: "0 0 14px" }}>
          Include software subscriptions, cyber insurance premiums, security-focused IT labor, awareness training, and backup/DR solutions.
          Exclude general IT hardware and non-security software licenses.
        </p>
        <div style={{ display: "flex", gap: 14, flexWrap: "wrap" }}>
          <div style={{ flex: 1, minWidth: 160 }}>
            <div style={{ color: TEXT_MUT, fontSize: 10, fontFamily: "monospace", textTransform: "uppercase", letterSpacing: "0.07em", marginBottom: 6 }}>
              Annual security budget
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <span style={{ color: GOLD, fontFamily: "monospace", fontWeight: 700 }}>$</span>
              <input
                type="number"
                placeholder="0"
                value={currentSpend}
                onChange={e => setCurrentSpend(e.target.value)}
                style={{
                  flex: 1, background: CARD, border: `1px solid ${BORDER}`,
                  borderRadius: 7, padding: "9px 12px",
                  color: TEXT_PRI, fontSize: 15, fontFamily: "monospace",
                }}
              />
            </div>
          </div>
          <div style={{ flex: 1, minWidth: 160 }}>
            <div style={{ color: TEXT_MUT, fontSize: 10, fontFamily: "monospace", textTransform: "uppercase", letterSpacing: "0.07em", marginBottom: 6 }}>
              Annual revenue (optional)
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <span style={{ color: TEXT_MUT, fontFamily: "monospace", fontWeight: 700 }}>$</span>
              <input
                type="number"
                placeholder="0"
                value={revenue}
                onChange={e => setRevenue(e.target.value)}
                style={{
                  flex: 1, background: CARD, border: `1px solid ${BORDER}`,
                  borderRadius: 7, padding: "9px 12px",
                  color: TEXT_PRI, fontSize: 15, fontFamily: "monospace",
                }}
              />
            </div>
          </div>
        </div>
      </div>

      {/* Verdict */}
      {cap > 0 && spend > 0 && (
        <div style={{
          background: vc.color + "0d",
          border: `1px solid ${vc.color}30`,
          borderLeft: `3px solid ${vc.color}`,
          borderRadius: 8, padding: "16px 20px",
        }}>
          <div style={{ color: vc.color, fontSize: 11, fontFamily: "monospace", fontWeight: 700, marginBottom: 6, textTransform: "uppercase", letterSpacing: "0.08em" }}>
            {vc.icon} {vc.label}
          </div>
          <p style={{ color: TEXT_DIM, fontSize: 13, fontFamily: "Georgia, serif", lineHeight: 1.65, margin: 0 }}>
            {verdict === "no-spend" && `With an expected loss of ${fmt(EL)} and no current security spend, your business absorbs the full weight of this risk uninsured. The Gordon–Loeb model recommends investing up to ${fmt(cap)} annually. Begin with the critical and high-priority findings below — several are low-cost or free to implement.`}
            {verdict === "severely-under" && `Your current spend of ${fmt(spend)} is significantly below the GL-recommended range. With ${fmt(cap - spend)} of headroom remaining before the economic ceiling, every additional dollar of security investment within this range has a positive expected net return.`}
            {verdict === "under" && `Your current spend of ${fmt(spend)} is ${fmt(cap - spend)} below the Gordon–Loeb ceiling of ${fmt(cap)}. Increasing investment up to this ceiling is economically justified — additional spend reduces expected loss by more than it costs.`}
            {verdict === "over" && `Your current spend of ${fmt(spend)} is ${fmt(spend - cap)} above the Gordon–Loeb ceiling of ${fmt(cap)}. Compliance requirements, contractual obligations, or risk tolerance may justify this — but above the ceiling, diminishing returns apply. Consider whether excess spend can be reallocated toward higher-ROI controls from the priority list below.`}
            {verdict === "optimal" && `Your current spend is near the Gordon–Loeb optimal range. Rather than increasing total budget, focus on directing existing spend toward the highest-priority findings below to maximize risk reduction per dollar.`}
          </p>
          {rev > 0 && (
            <div style={{ color: TEXT_MUT, fontSize: 11, fontFamily: "monospace", marginTop: 8 }}>
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
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 14 }}>
        <span style={{ color: TEXT_MUT, fontFamily: "monospace", fontSize: 10, textTransform: "uppercase", letterSpacing: "0.1em" }}>
          Priority Actions — from your confirmed findings
        </span>
      </div>
      <p style={{ color: TEXT_DIM, fontSize: 13, fontFamily: "Georgia, serif", lineHeight: 1.65, margin: "0 0 16px" }}>
        These findings represent your most exploitable attack paths — the ones that contribute most to your breach probability (v) and that, if remediated, would deliver the largest reduction in expected loss per dollar spent. Each finding's v contribution is shown so you can prioritize by economic impact, not just by label.
      </p>
      {top.map(f => {
        const color = SEV_COLORS[f.severity] || TEXT_MUT;
        return (
          <div key={f.id} style={{
            background: BG, border: `1px solid ${BORDER}`,
            borderLeft: `3px solid ${color}`,
            borderRadius: 8, padding: "14px 18px", marginBottom: 10,
          }}>
            <div style={{ display: "flex", gap: 10, alignItems: "center", marginBottom: 8, flexWrap: "wrap" }}>
              <SevBadge sev={f.severity} />
              <span style={{ color: TEXT_SEC, fontSize: 13, fontWeight: 700, fontFamily: "Georgia, serif", flex: 1 }}>
                {f.name}
              </span>
              <span style={{ color: TEXT_MUT, fontSize: 10, fontFamily: "monospace", flexShrink: 0 }}>
                v contribution: +{pct(findingWeight(f))}
              </span>
            </div>
            <p style={{ color: TEXT_DIM, fontSize: 13, fontFamily: "Georgia, serif", lineHeight: 1.6, margin: "0 0 8px" }}>
              {f.recommendation}
            </p>
            {f.business_impact && (
              <p style={{ color: TEXT_MUT, fontSize: 12, fontFamily: "Georgia, serif", lineHeight: 1.55, margin: "0 0 8px", fontStyle: "italic" }}>
                {f.business_impact.slice(0, 160)}…
              </p>
            )}
            <div style={{ display: "flex", gap: 14, flexWrap: "wrap" }}>
              <span style={{ color: TEXT_MUT, fontSize: 10, fontFamily: "monospace" }}>{f.attack_tactic}</span>
              <span style={{ color: TEXT_MUT, fontSize: 10, fontFamily: "monospace" }}>{f.attack_technique}</span>
              {f.references?.map(r => (
                <a key={r} href={r} target="_blank" rel="noreferrer"
                  style={{ color: TEXT_MUT, fontSize: 10, fontFamily: "monospace", textDecoration: "underline", textDecorationColor: BORDER2 }}>
                  {r.replace("https://", "").split("/")[0]}
                </a>
              ))}
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ─── Report generator ─────────────────────────────────────────────────────────
function generateReport({ v, L, EL, cap, spend, revenue, threatModel, assets, extraFindings }) {
  const scoreColor = threatModel.summary.overall_risk_score >= 70 ? "#e05c5c"
    : threatModel.summary.overall_risk_score >= 40 ? "#e8a020" : "#60b06e";
  const sevColors = { critical: "#e05c5c", high: "#e8a020", medium: "#5b8dd4", low: "#60b06e" };
  const allFindings = [...threatModel.findings, ...extraFindings.filter(f => f.name)];

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
        <span style="color:#666;font-size:11px;font-family:monospace;margin-left:auto;">v contribution: +${pct(findingWeight(f))}</span>
      </div>
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
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:Georgia,serif;background:#fff;color:#1a202c;font-size:14px}.page{max-width:820px;margin:0 auto;padding:48px 40px}.header{background:#0b1117;color:#fff;padding:32px 40px;border-radius:10px;margin-bottom:32px}.header h1{font-size:22px;font-weight:800;color:#c8922a;margin-bottom:4px}.header .sub{color:#94a3b8;font-size:13px}.header .date{color:#4a5568;font-size:11px;margin-top:6px;font-family:monospace}h2{font-size:14px;font-weight:700;color:#0b1117;text-transform:uppercase;letter-spacing:.07em;margin:28px 0 12px;border-bottom:2px solid #c8922a;padding-bottom:6px}.stats{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:20px}.stat{background:#f7fafc;border:1px solid #e2e8f0;border-radius:8px;padding:12px 16px;flex:1;min-width:120px}.stat .lbl{font-size:10px;text-transform:uppercase;letter-spacing:.07em;color:#718096;margin-bottom:4px;font-family:monospace}.stat .val{font-size:20px;font-weight:800;font-family:monospace}.stat.gold .val{color:#c8922a}.formula{background:#0b1117;color:#c8922a;padding:12px 18px;border-radius:6px;font-family:monospace;font-size:13px;margin:12px 0}.verdict{padding:14px 18px;border-radius:8px;margin:16px 0;border-left:3px solid #c8922a;background:#fffbeb;font-size:13px;line-height:1.65}table{width:100%;border-collapse:collapse;margin:12px 0;font-size:13px}th{background:#0b1117;color:#94a3b8;text-align:left;padding:8px 12px;font-size:10px;text-transform:uppercase;letter-spacing:.07em;font-family:monospace}td{padding:8px 12px}.citation{background:#f7fafc;border-left:3px solid #c8922a;padding:12px 16px;margin:12px 0;font-size:11px;color:#4a5568;font-style:italic;line-height:1.7}.footer{margin-top:48px;padding-top:16px;border-top:1px solid #e2e8f0;color:#718096;font-size:10px;text-align:center;font-family:monospace}@media print{.page{padding:20px}}</style>
</head><body><div class="page">
<div class="header"><h1>MicroSOC — Gordon-Loeb Economic Report</h1>
<div class="sub">Cybersecurity Investment Analysis · PASTA + MITRE ATT&amp;CK · Gordon-Loeb (2002)</div>
<div class="date">Generated: ${new Date().toLocaleDateString("en-US",{year:"numeric",month:"long",day:"numeric"})} · Framework: Gordon &amp; Loeb, ACM TISSEC 2002</div></div>
<h2>Executive Summary</h2>
<div class="stats">
  <div class="stat"><div class="lbl">Risk Score</div><div class="val" style="color:${scoreColor}">${threatModel.summary.overall_risk_score}/100</div></div>
  <div class="stat"><div class="lbl">Total Findings</div><div class="val">${allFindings.length}</div></div>
  <div class="stat"><div class="lbl">Vulnerability (v)</div><div class="val">${pct(v)}</div></div>
  <div class="stat"><div class="lbl">Expected Loss (v×L)</div><div class="val">${fmt(EL)}</div></div>
  <div class="stat gold"><div class="lbl">GL Investment Cap</div><div class="val">${fmt(cap)}</div></div>
  ${spend > 0 ? `<div class="stat"><div class="lbl">Current Spend</div><div class="val">${fmt(spend)}</div></div>` : ""}
</div>
<div class="formula">z* ≤ (1/e) × v × L = 0.3679 × ${pct(v)} × ${fmt(L)} = ${fmt(cap)}</div>
<div class="verdict">${verdictText}</div>
${parseFloat(revenue) > 0 ? `<p style="font-size:12px;color:#718096;margin-top:8px;font-family:monospace;">Security spend as % of revenue: ${((spend/parseFloat(revenue))*100).toFixed(1)}%</p>` : ""}
<h2>Threat Findings (${allFindings.length}${extraFindings.filter(f=>f.name).length > 0 ? `, including ${extraFindings.filter(f=>f.name).length} added manually` : ""})</h2>
${findingsHTML}
<h2>Asset Inventory (L = ${fmt(L)})</h2>
<table>
<tr><th>Asset / Loss Category</th><th style="text-align:right">Estimated Value</th></tr>
${assetsHTML}
<tr><td style="font-weight:700;padding:8px 12px;">Total (L)</td><td style="text-align:right;font-weight:800;color:#c8922a;font-family:monospace;padding:8px 12px;">${fmt(L)}</td></tr>
</table>
<h2>Investment Scenarios</h2>
<table>
<tr><th>Scenario</th><th style="text-align:right">Amount</th><th>Notes</th></tr>
<tr><td style="padding:8px 12px;">Conservative (10%)</td><td style="text-align:right;padding:8px 12px;font-family:monospace;">${fmt(0.10*EL)}</td><td style="padding:8px 12px;">Address critical findings only</td></tr>
<tr style="background:#f7fafc"><td style="padding:8px 12px;">Moderate (20%)</td><td style="text-align:right;padding:8px 12px;font-family:monospace;">${fmt(0.20*EL)}</td><td style="padding:8px 12px;">Recommended starting point for most SMEs</td></tr>
<tr><td style="padding:8px 12px;font-weight:700;">GL Maximum (37%)</td><td style="text-align:right;padding:8px 12px;font-family:monospace;font-weight:700;color:#c8922a;">${fmt(cap)}</td><td style="padding:8px 12px;">Economic upper bound — positive net value below this</td></tr>
${spend > 0 ? `<tr style="background:#f7fafc"><td style="padding:8px 12px;">Your current spend</td><td style="text-align:right;padding:8px 12px;font-family:monospace;">${fmt(spend)}</td><td style="padding:8px 12px;">${spend > cap ? "Above GL cap" : "Within GL range"}</td></tr>` : ""}
</table>
<h2>Citations</h2>
<div class="citation">
Gordon, L. A., &amp; Loeb, M. P. (2002). The Economics of Information Security Investment. <em>ACM Transactions on Information and System Security, 5</em>(4), 438–457. https://doi.org/10.1145/581271.581274<br/><br/>
Gordon, L. A., Loeb, M. P., Lucyshyn, W., &amp; Zhou, L. (2018). Empirical Evidence on the Determinants of Cybersecurity Investments in Private Sector Firms. <em>Journal of Information Science, 9</em>(2). https://doi.org/10.4236/jis.2018.92010<br/><br/>
Gordon, L. A., et al. (2020). Integrating cost–benefit analysis into the NIST Cybersecurity Framework via the Gordon–Loeb Model. <em>Journal of Cybersecurity, 6</em>(1), tyaa005. https://doi.org/10.1093/cybsec/tyaa005
</div>
<p style="margin-top:20px;font-size:12px;color:#718096;line-height:1.7;">This report is generated by MicroSOC for educational and planning purposes. It is not a substitute for a professional cybersecurity risk assessment. The Gordon–Loeb model provides a theoretical framework; actual optimal investment depends on your specific threat environment, regulatory obligations, and organizational risk tolerance.</p>
<div class="footer">MicroSOC · PASTA + MITRE ATT&amp;CK · Gordon-Loeb Economic Module · ${new Date().toISOString().slice(0,10)}</div>
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
  const [assets,        setAssets]        = useState([{ id: 1, name: "", value: "" }]);
  const [extraFindings, setExtraFindings] = useState([]);
  const [manualV,       setManualV]       = useState(null);
  const [currentSpend,  setCurrentSpend]  = useState("");
  const [revenue,       setRevenue]       = useState("");

  // All derived values recalculate instantly when any input changes
  const v = useMemo(() => {
    if (manualV !== null) return manualV;
    const base  = computeV(threatModel.findings);
    const extra = computeV(extraFindings.filter(f => f.name));
    return Math.min(base + extra, 0.95);
  }, [threatModel.findings, extraFindings, manualV]);

  const L   = useMemo(() => assets.reduce((s, a) => s + (parseFloat(a.value) || 0), 0), [assets]);
  const EL  = v * L;
  const cap = GL_CAP * EL;

  const allFindings = [...threatModel.findings, ...extraFindings.filter(f => f.name)];

  return (
    <div style={{
      minHeight: "100vh",
      background: BG,
      backgroundImage: `
        radial-gradient(ellipse 60% 50% at 15% 0%,   rgba(200,146,42,0.04) 0%, transparent 60%),
        radial-gradient(ellipse 50% 40% at 85% 100%, rgba(91,141,212,0.04) 0%, transparent 60%)
      `,
      fontFamily: "Georgia, serif",
      padding: "48px 20px 100px",
    }}>
      <div style={{ maxWidth: 1100, margin: "0 auto" }}>

        {/* ── Page header ── */}
        <div style={{ marginBottom: 40 }}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 22 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <div style={{ width: 8, height: 8, borderRadius: "50%", background: GOLD, boxShadow: `0 0 10px ${GOLD}88` }} />
              <span style={{ color: TEXT_MUT, fontSize: 11, fontFamily: "monospace", letterSpacing: "0.16em", textTransform: "uppercase" }}>
                MicroSOC · Economic Analysis
              </span>
            </div>
            <button
              onClick={onBack}
              style={{
                background: "none", border: `1px solid ${BORDER}`, borderRadius: 6,
                color: TEXT_DIM, cursor: "pointer", fontSize: 12,
                padding: "5px 14px", fontFamily: "Georgia, serif",
              }}
            >
              ← Back to threat report
            </button>
          </div>
          <h1 style={{ fontSize: 36, color: TEXT_PRI, margin: "0 0 6px", lineHeight: 1.1, fontWeight: 700, letterSpacing: "-0.5px" }}>
            Gordon–Loeb Investment Model
          </h1>
          <p style={{ color: TEXT_DIM, fontSize: 15, margin: 0, lineHeight: 1.7, maxWidth: 560 }}>
            Your <strong style={{ color: TEXT_SEC }}>{threatModel.summary.total_findings} confirmed findings</strong> feed directly into this analysis.
            Enter your asset value to see your complete investment picture — everything else is computed automatically.
          </p>
        </div>

        {/* ── Main card ── */}
        <div style={{
          background: CARD, border: `1px solid ${BORDER}`, borderRadius: 16,
          padding: "36px 44px",
          boxShadow: "0 8px 60px rgba(0,0,0,0.5), inset 0 1px 0 rgba(255,255,255,0.03)",
        }}>

          <GLIntro threatModel={threatModel} />
          <Divider />

          <VulnerabilitySection
            threatModel={threatModel}
            extraFindings={extraFindings}
            setExtraFindings={setExtraFindings}
            manualV={manualV}
            setManualV={setManualV}
          />
          <Divider />

          <AssetValueSection
            assets={assets}
            setAssets={setAssets}
            surveyAnswers={surveyAnswers}
          />
          <Divider />

          <ResultsSection
            v={v}
            L={L}
            threatModel={threatModel}
            currentSpend={currentSpend}
            setCurrentSpend={setCurrentSpend}
            revenue={revenue}
            setRevenue={setRevenue}
          />

          {L > 0 && (
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
              Gordon, L. A., Loeb, M. P., Lucyshyn, W., &amp; Zhou, L. (2018). Empirical Evidence on the
              Determinants of Cybersecurity Investments in Private Sector Firms.{" "}
              <em>Journal of Information Science, 9</em>(2).<br />
              Gordon, L. A., et al. (2020). Integrating cost–benefit analysis into the NIST Cybersecurity
              Framework via the Gordon–Loeb Model. <em>Journal of Cybersecurity, 6</em>(1), tyaa005.
            </p>
          </div>

          {/* Download */}
          <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 28, paddingTop: 24, borderTop: `1px solid ${BORDER}` }}>
            <button
              onClick={() => generateReport({ v, L, EL, cap, spend: parseFloat(currentSpend)||0, revenue, threatModel, assets, extraFindings })}
              disabled={L === 0}
              style={{
                padding: "12px 28px", borderRadius: 8, border: "none",
                background: L > 0 ? GOLD : BORDER,
                color: L > 0 ? "#0b1117" : TEXT_MUT,
                cursor: L > 0 ? "pointer" : "not-allowed",
                fontSize: 14, fontWeight: 700, fontFamily: "Georgia, serif",
                boxShadow: L > 0 ? `0 2px 16px ${GOLD}44` : "none",
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
