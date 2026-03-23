import { useState, useEffect } from "react";

// ─── Design tokens — exact match with Survey.jsx ──────────────────────────────
const BG        = "#0b1117";
const CARD      = "#0e1822";
const BORDER    = "#141e28";
const BORDER2   = "#1e2e3e";
const GOLD      = "#c8922a";
const TEXT_PRI  = "#e8ddd0";
const TEXT_SEC  = "#8a9eb0";
const TEXT_DIM  = "#8a9eb0";
const TEXT_MUT  = "#2e4458";
const CRIT      = "#e05c5c";
const HIGH_C    = "#e8a020";
const MED_C     = "#5b8dd4";
const LOW_C     = "#60b06e";

const SEV_COLORS = { critical: CRIT, high: HIGH_C, medium: MED_C, low: LOW_C };

// ─── Module definitions ───────────────────────────────────────────────────────
const MODULES = [
  {
    num: "I",
    id: "survey",
    label: "Risk Assessment",
    tag: "PASTA + MITRE ATT&CK",
    tagColor: GOLD,
    desc: "A guided 7-stage survey that maps your business environment to a prioritized threat profile. No technical knowledge required.",
    detail: "Covers identity, endpoints, email, access controls, detection gaps, and recovery capability across all PASTA stages.",
    icon: "⬡",
    color: GOLD,
    action: "primary",
  },
  {
    num: "II",
    id: "threat-model",
    label: "Threat Model",
    tag: "27 RULE ENGINE",
    tagColor: CRIT,
    desc: "Generated automatically from your survey responses. Every finding is mapped to MITRE ATT&CK tactics, techniques, and PASTA stages.",
    detail: "Findings are ranked by severity and likelihood. Each includes a plain-language business impact statement and remediation steps.",
    icon: "⬡",
    color: CRIT,
    action: "results-only",
  },
  {
    num: "III",
    id: "misconfig",
    label: "Misconfig Guide",
    tag: "MODULE 5",
    tagColor: "#4ea8a0",
    desc: "All 27 security checks the platform monitors — with remediation guidance, CISA/NIST references, and your flagged findings highlighted.",
    detail: "Filter by severity, search by keyword, or view flagged-first. Generates a downloadable PDF-ready report.",
    icon: "⬡",
    color: "#4ea8a0",
    action: "always",
  },
  {
    num: "IV",
    id: "economic",
    label: "Economic Analysis",
    tag: "GORDON–LOEB 2002",
    tagColor: MED_C,
    desc: "Translates your confirmed findings into a principled cybersecurity budget using the Gordon-Loeb model — the academic gold standard.",
    detail: "Derives vulnerability (v) directly from your threat findings. Calculates your optimal investment ceiling (z* ≤ 1/e × v × L).",
    icon: "⬡",
    color: MED_C,
    action: "results-only",
  },
];

// ─── Score helpers ─────────────────────────────────────────────────────────────
function riskLabel(score) {
  if (score >= 70) return { text: "High Risk",      color: CRIT   };
  if (score >= 40) return { text: "Moderate Risk",  color: HIGH_C };
  return              { text: "Lower Risk",          color: LOW_C  };
}

// ─── Sub-components ───────────────────────────────────────────────────────────

const Dot = ({ on, color = GOLD }) => (
  <div style={{
    width: 7, height: 7, borderRadius: "50%",
    background: on ? color : TEXT_MUT,
    boxShadow: on ? `0 0 8px ${color}99` : "none",
    transition: "all 0.3s",
  }} />
);

function ModuleCard({ mod, hasResults, onStartSurvey, onOpenMisconfig, onOpenEconomic }) {
  const [hovered, setHovered] = useState(false);

  const isResultsOnly = mod.action === "results-only" && !hasResults;
  const isLocked = isResultsOnly;

  const handleClick = () => {
    if (isLocked) return;
    if (mod.id === "survey")    onStartSurvey();
    if (mod.id === "misconfig") onOpenMisconfig();
    if (mod.id === "economic" && hasResults) onOpenEconomic();
  };

  const borderColor = isLocked
    ? BORDER
    : hovered
    ? mod.color + "60"
    : BORDER;

  return (
    <div
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      onClick={handleClick}
      style={{
        background: CARD,
        border: `1px solid ${borderColor}`,
        borderTop: `3px solid ${isLocked ? BORDER2 : mod.color}`,
        borderRadius: 12,
        padding: "22px 24px",
        cursor: isLocked ? "default" : "pointer",
        opacity: 1,
        transition: "border-color 0.2s, transform 0.15s, box-shadow 0.2s",
        transform: hovered && !isLocked ? "translateY(-2px)" : "none",
        boxShadow: hovered && !isLocked ? `0 8px 32px rgba(0,0,0,0.3), 0 0 0 1px ${mod.color}20` : "none",
      }}
    >
      {/* Header row */}
      <div style={{ display: "flex", alignItems: "flex-start", gap: 10, marginBottom: 14 }}>
        <div style={{
          width: 32, height: 32, borderRadius: 8, flexShrink: 0,
          background: isLocked ? BORDER + "40" : mod.color + "15",
          border: `1.5px solid ${isLocked ? BORDER2 : mod.color + "40"}`,
          display: "flex", alignItems: "center", justifyContent: "center",
          fontSize: 9, fontFamily: "monospace", fontWeight: 900,
          color: isLocked ? TEXT_MUT : mod.color,
        }}>
          {mod.num}
        </div>
        <div>
          <div style={{
            color: isLocked ? TEXT_MUT : TEXT_PRI,
            fontSize: 15, fontWeight: 700, fontFamily: "Georgia, serif", lineHeight: 1.2,
            marginBottom: 6,
          }}>
            {mod.label}
          </div>
          <span style={{
            display: "inline-block",
            padding: "2px 8px", borderRadius: 4,
            background: isLocked ? "transparent" : mod.tagColor + "15",
            border: `1px solid ${isLocked ? BORDER2 : mod.tagColor + "35"}`,
            color: isLocked ? TEXT_MUT : mod.tagColor,
            fontSize: 9, fontFamily: "monospace", fontWeight: 700,
            textTransform: "uppercase", letterSpacing: "0.06em",
          }}>
            {mod.tag}
          </span>
        </div>
      </div>

      {/* Description */}
      <p style={{
        color: isLocked ? TEXT_MUT : TEXT_DIM,
        fontSize: 13, fontFamily: "Georgia, serif", lineHeight: 1.65,
        margin: "0 0 14px",
      }}>
        {mod.desc}
      </p>

      {/* Detail */}
      <p style={{
        color: TEXT_MUT,
        fontSize: 12, fontFamily: "Georgia, serif", lineHeight: 1.6,
        margin: "0 0 16px",
      }}>
        {mod.detail}
      </p>

      {/* CTA row */}
      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
        {isResultsOnly ? (
          <span style={{ color: TEXT_MUT, fontSize: 11, fontFamily: "monospace" }}>
            Complete an assessment to unlock
          </span>
        ) : (
          <>
            <Dot on color={mod.color} />
            <span style={{
              color: hovered ? mod.color : TEXT_DIM,
              fontSize: 12, fontFamily: "monospace",
              transition: "color 0.15s",
            }}>
              {mod.id === "survey"   && (hasResults ? "Start new assessment →" : "Start assessment →")}
              {mod.id === "misconfig" && "Browse guide →"}
              {mod.id === "economic"  && "Open model →"}
            </span>
          </>
        )}
      </div>
    </div>
  );
}

// ─── Last results banner ──────────────────────────────────────────────────────
function LastResultsBanner({ threatModel, onViewResults, onOpenEconomic, onOpenMisconfig }) {
  const { summary } = threatModel;
  const rl = riskLabel(summary.overall_risk_score);
  const scoreColor = rl.color;

  return (
    <div style={{
      background: CARD,
      border: `1px solid ${BORDER}`,
      borderLeft: `3px solid ${scoreColor}`,
      borderRadius: 12,
      padding: "20px 26px",
      marginBottom: 28,
      display: "flex", alignItems: "center",
      justifyContent: "space-between", flexWrap: "wrap", gap: 16,
    }}>
      <div style={{ display: "flex", alignItems: "center", gap: 20, flexWrap: "wrap" }}>
        <div>
          <div style={{ color: TEXT_MUT, fontSize: 10, fontFamily: "monospace", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 4 }}>
            Last Assessment
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <div style={{ textAlign: "center" }}>
              <div style={{ fontSize: 32, fontWeight: 700, color: scoreColor, fontFamily: "monospace", lineHeight: 1 }}>
                {summary.overall_risk_score}
              </div>
              <div style={{ color: TEXT_MUT, fontSize: 9, fontFamily: "monospace", marginTop: 2 }}>/ 100</div>
            </div>
            <div>
              <div style={{ color: scoreColor, fontSize: 14, fontWeight: 700, fontFamily: "Georgia, serif" }}>{rl.text}</div>
              <div style={{ color: TEXT_MUT, fontSize: 12, fontFamily: "monospace", marginTop: 2 }}>
                {summary.total_findings} finding{summary.total_findings !== 1 ? "s" : ""}
                {summary.critical > 0 && <span style={{ color: CRIT }}> · {summary.critical} critical</span>}
                {summary.high > 0 && <span style={{ color: HIGH_C }}> · {summary.high} high</span>}
              </div>
            </div>
          </div>
        </div>
      </div>

      <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
        <button
          onClick={onViewResults}
          style={{
            padding: "9px 18px", borderRadius: 7, border: `1px solid ${BORDER2}`,
            background: "transparent", color: TEXT_DIM, cursor: "pointer",
            fontSize: 12, fontFamily: "Georgia, serif",
          }}
        >
          View threat report
        </button>
        <button
          onClick={onOpenMisconfig}
          style={{
            padding: "9px 18px", borderRadius: 7, border: "1px solid #4ea8a040",
            background: "transparent", color: "#4ea8a0", cursor: "pointer",
            fontSize: 12, fontFamily: "Georgia, serif",
          }}
        >
          Misconfig guide
        </button>
        <button
          onClick={onOpenEconomic}
          style={{
            padding: "9px 18px", borderRadius: 7, border: "none",
            background: GOLD + "18", color: GOLD, cursor: "pointer",
            fontSize: 12, fontFamily: "Georgia, serif", fontWeight: 700,
            border: `1px solid ${GOLD}35`,
          }}
        >
          Economic analysis →
        </button>
      </div>
    </div>
  );
}

// ─── Main component ───────────────────────────────────────────────────────────
export default function Home({ onStartSurvey, onOpenMisconfig, onOpenEconomic, lastThreatModel, onViewLastResults }) {
  const [visible, setVisible] = useState(false);
  useEffect(() => { setTimeout(() => setVisible(true), 40); }, []);

  const hasResults = !!lastThreatModel;

  return (
    <div style={{
      minHeight: "100vh",
      background: BG,
      backgroundImage: `
        radial-gradient(ellipse 70% 55% at 10% 0%,   rgba(200,146,42,0.05)  0%, transparent 55%),
        radial-gradient(ellipse 50% 40% at 90% 100%, rgba(91,141,212,0.04)  0%, transparent 55%),
        radial-gradient(ellipse 40% 35% at 50% 50%,  rgba(200,146,42,0.02)  0%, transparent 60%)
      `,
      fontFamily: "Georgia, serif",
      padding: "52px 24px 100px",
      opacity: visible ? 1 : 0,
      transform: visible ? "none" : "translateY(10px)",
      transition: "opacity 0.5s, transform 0.5s",
    }}>
      <div style={{ maxWidth: 1100, margin: "0 auto" }}>

        {/* ── Wordmark ── */}
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 56 }}>
          <div style={{
            width: 9, height: 9, borderRadius: "50%", background: GOLD,
            boxShadow: `0 0 14px ${GOLD}99`,
          }} />
          <span style={{
            color: "#3a5568", fontSize: 11, fontFamily: "monospace",
            letterSpacing: "0.18em", textTransform: "uppercase",
          }}>
            MicroSOC
          </span>
          <span style={{ color: BORDER2, fontFamily: "monospace", fontSize: 10 }}>·</span>
          <span style={{ color: "#2e4458", fontSize: 11, fontFamily: "monospace", letterSpacing: "0.08em" }}>
            SME Cyber Risk Platform
          </span>
        </div>

        {/* ── Hero ── */}
        <div style={{ marginBottom: 52 }}>
          <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", flexWrap: "wrap", gap: 24 }}>
            <div style={{ maxWidth: 580 }}>
              <h1 style={{
                fontSize: 44, color: TEXT_PRI, margin: "0 0 16px",
                lineHeight: 1.08, fontWeight: 700, letterSpacing: "-0.8px",
              }}>
                Understand your<br />
                <span style={{ color: GOLD }}>cyber risk</span> — clearly.
              </h1>
              <p style={{
                color: TEXT_DIM, fontSize: 16, lineHeight: 1.75,
                margin: "0 0 28px", maxWidth: 520,
              }}>
                A free, local-first security analysis platform for small and medium businesses.
                No agents. No cloud upload. No technical expertise required.
              </p>
              <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
                <button
                  onClick={onStartSurvey}
                  style={{
                    padding: "13px 32px", borderRadius: 9, border: "none",
                    background: GOLD, color: "#0b1117", cursor: "pointer",
                    fontSize: 15, fontWeight: 700, fontFamily: "Georgia, serif",
                    boxShadow: `0 4px 24px ${GOLD}55`,
                    transition: "transform 0.15s, box-shadow 0.15s",
                  }}
                  onMouseEnter={e => { e.currentTarget.style.transform = "translateY(-1px)"; e.currentTarget.style.boxShadow = `0 6px 28px ${GOLD}66`; }}
                  onMouseLeave={e => { e.currentTarget.style.transform = "none"; e.currentTarget.style.boxShadow = `0 4px 24px ${GOLD}55`; }}
                >
                  {hasResults ? "Start New Assessment →" : "Start Risk Assessment →"}
                </button>
                <button
                  onClick={onOpenMisconfig}
                  style={{
                    padding: "13px 24px", borderRadius: 9,
                    border: `1px solid ${BORDER2}`,
                    background: "transparent", color: TEXT_DIM, cursor: "pointer",
                    fontSize: 15, fontFamily: "Georgia, serif",
                    transition: "border-color 0.15s, color 0.15s",
                  }}
                  onMouseEnter={e => { e.currentTarget.style.borderColor = "#4ea8a050"; e.currentTarget.style.color = "#4ea8a0"; }}
                  onMouseLeave={e => { e.currentTarget.style.borderColor = BORDER2; e.currentTarget.style.color = TEXT_DIM; }}
                >
                  Browse Misconfig Guide
                </button>
              </div>
            </div>

            {/* ── Quick stats ── */}
            <div style={{
              display: "flex", flexDirection: "column", gap: 8, minWidth: 200,
            }}>
              {[
                { n: "27",  label: "Security checks",      color: CRIT },
                { n: "7",   label: "Step PASTA Model",  color: MED_C  },
                { n: "100%", label: "All data stays local", color: GOLD  },
                { n: "Free", label: "No account required",  color: LOW_C },
              ].map(({ n, label, color }) => (
                <div key={label} style={{
                  background: CARD, border: `1px solid ${BORDER}`,
                  borderRadius: 8, padding: "10px 16px",
                  display: "flex", alignItems: "center", gap: 12,
                }}>
                  <span style={{ color, fontSize: 16, fontWeight: 700, fontFamily: "monospace", width: 48, flexShrink: 0 }}>{n}</span>
                  <span style={{ color: TEXT_DIM, fontSize: 12, fontFamily: "Georgia, serif" }}>{label}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* ── Last results banner ── */}
        {hasResults && (
          <LastResultsBanner
            threatModel={lastThreatModel}
            onViewResults={onViewLastResults}
            onOpenEconomic={onOpenEconomic}
            onOpenMisconfig={onOpenMisconfig}
          />
        )}

        {/* ── Module grid ── */}
        <div style={{ marginBottom: 16 }}>
          <div style={{
            display: "flex", alignItems: "center", gap: 12, marginBottom: 20,
          }}>
            <div style={{ color: TEXT_MUT, fontSize: 10, fontFamily: "monospace", textTransform: "uppercase", letterSpacing: "0.12em" }}>
              Platform Modules
            </div>
            <div style={{ flex: 1, height: 1, background: BORDER }} />
          </div>

          <div style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fill, minmax(260px, 1fr))",
            gap: 14,
          }}>
            {MODULES.map(mod => (
              <ModuleCard
                key={mod.id}
                mod={mod}
                hasResults={hasResults}
                onStartSurvey={onStartSurvey}
                onOpenMisconfig={onOpenMisconfig}
                onOpenEconomic={onOpenEconomic}
              />
            ))}
          </div>
        </div>

        {/* ── Methodology strip ── */}
        <div style={{
          marginTop: 40, padding: "22px 28px",
          background: CARD, border: `1px solid ${BORDER}`, borderRadius: 12,
        }}>
          <div style={{ color: TEXT_MUT, fontSize: 10, fontFamily: "monospace", textTransform: "uppercase", letterSpacing: "0.1em", marginBottom: 14 }}>
            Methodology & Sources
          </div>
          <div style={{ display: "flex", gap: 24, flexWrap: "wrap" }}>
            {[
              { framework: "PASTA",         desc: "Process for Attack Simulation and Threat Analysis — 7-stage threat modeling" },
              { framework: "MITRE ATT&CK",  desc: "Adversarial tactics and techniques linked to every finding" },
              { framework: "NIST CSF",      desc: "Control mappings and remediation guidance" },
              { framework: "Gordon–Loeb",   desc: "ACM TISSEC 2002 — economic model for optimal security investment" },
              { framework: "CISA / FBI IC3", desc: "Real-world SME threat intelligence and advisory data" },
            ].map(({ framework, desc }) => (
              <div key={framework} style={{ minWidth: 150, flex: 1 }}>
                <div style={{ color: TEXT_SEC, fontSize: 12, fontWeight: 700, fontFamily: "monospace", marginBottom: 3 }}>{framework}</div>
                <div style={{ color: TEXT_MUT, fontSize: 12, fontFamily: "Georgia, serif", lineHeight: 1.5 }}>{desc}</div>
              </div>
            ))}
          </div>
        </div>

        {/* ── Footer ── */}
        <p style={{
          textAlign: "center", color: "#1a2a38", fontSize: 11,
          marginTop: 28, fontFamily: "monospace",
          lineHeight: 1.7,
        }}>
          All responses and data processed locally · No telemetry · No external data transmission<br />
          Built for SMEs with &lt;50 employees operating under tight security budgets
        </p>

      </div>
    </div>
  );
}
