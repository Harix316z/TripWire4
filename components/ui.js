"use client";

export function Panel({ children, style }) {
  return (
    <div
      className="grain"
      style={{
        background: "var(--bg-panel)",
        border: "1px solid var(--line)",
        borderRadius: "10px",
        ...style,
      }}
    >
      {children}
    </div>
  );
}

export function SeverityDot({ level }) {
  const colors = {
    critical: "var(--crit)",
    high: "var(--high)",
    medium: "var(--med)",
    med: "var(--med)",
    moderate: "var(--med)",
    low: "var(--low)",
    ok: "var(--ok)",
    unknown: "var(--ink-faint)",
  };
  const c = colors[String(level).toLowerCase()] || "var(--ink-faint)";
  return (
    <span
      style={{
        display: "inline-block",
        width: 8,
        height: 8,
        borderRadius: "50%",
        background: c,
        marginRight: 8,
        boxShadow: `0 0 8px ${c}`,
        flexShrink: 0,
      }}
    />
  );
}

export function Badge({ children, tone = "default" }) {
  const tones = {
    default: { bg: "var(--bg-raised)", fg: "var(--ink-dim)", bd: "var(--line)" },
    amber: { bg: "var(--amber-glow)", fg: "var(--amber)", bd: "rgba(255,177,0,0.35)" },
    critical: { bg: "rgba(255,92,92,0.12)", fg: "var(--crit)", bd: "rgba(255,92,92,0.35)" },
    high: { bg: "rgba(255,154,61,0.12)", fg: "var(--high)", bd: "rgba(255,154,61,0.35)" },
    medium: { bg: "rgba(255,210,61,0.12)", fg: "var(--med)", bd: "rgba(255,210,61,0.35)" },
    low: { bg: "rgba(107,208,255,0.12)", fg: "var(--low)", bd: "rgba(107,208,255,0.35)" },
    ok: { bg: "rgba(74,222,128,0.12)", fg: "var(--ok)", bd: "rgba(74,222,128,0.35)" },
  };
  const t = tones[tone] || tones.default;
  return (
    <span
      className="mono"
      style={{
        display: "inline-block",
        padding: "2px 8px",
        fontSize: "11px",
        letterSpacing: "0.03em",
        borderRadius: "5px",
        background: t.bg,
        color: t.fg,
        border: `1px solid ${t.bd}`,
        textTransform: "uppercase",
      }}
    >
      {children}
    </span>
  );
}

export function Button({ children, onClick, disabled, variant = "primary", type = "button", style }) {
  const base = {
    fontFamily: "var(--font-mono)",
    fontSize: "13px",
    fontWeight: 500,
    padding: "10px 18px",
    borderRadius: "7px",
    cursor: disabled ? "not-allowed" : "pointer",
    opacity: disabled ? 0.5 : 1,
    border: "1px solid transparent",
    transition: "all 120ms ease",
    letterSpacing: "0.01em",
    ...style,
  };
  const variants = {
    primary: { background: "var(--amber)", color: "#161200", border: "1px solid var(--amber)" },
    ghost: { background: "transparent", color: "var(--ink-dim)", border: "1px solid var(--line)" },
  };
  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled}
      style={{ ...base, ...variants[variant] }}
    >
      {children}
    </button>
  );
}

export function Field({ label, children }) {
  return (
    <label style={{ display: "block", marginBottom: "14px" }}>
      <div
        className="mono"
        style={{
          fontSize: "11px",
          color: "var(--ink-faint)",
          textTransform: "uppercase",
          letterSpacing: "0.06em",
          marginBottom: "6px",
        }}
      >
        {label}
      </div>
      {children}
    </label>
  );
}

export const inputStyle = {
  width: "100%",
  background: "var(--bg-raised)",
  border: "1px solid var(--line)",
  borderRadius: "7px",
  padding: "11px 12px",
  color: "var(--ink)",
  fontFamily: "var(--font-mono)",
  fontSize: "13.5px",
  outline: "none",
};
