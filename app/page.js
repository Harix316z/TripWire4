"use client";

import { useState, useCallback } from "react";
import SessionLog from "@/components/SessionLog";
import HashTool from "@/components/HashTool";
import HeadersTool from "@/components/HeadersTool";
import SecretsTool from "@/components/SecretsTool";
import VulnTool from "@/components/VulnTool";

const TOOLS = [
  { id: "hash", num: "01", label: "Hash ID", full: "Hash Identifier", component: HashTool },
  { id: "headers", num: "02", label: "Headers", full: "HTTP Header Auditor", component: HeadersTool },
  { id: "secrets", num: "03", label: "Secrets", full: "Secrets Scanner", component: SecretsTool },
  { id: "vuln", num: "04", label: "Vuln Lookup", full: "Dependency Vulnerability Lookup", component: VulnTool },
];

function timestamp() {
  return new Date().toTimeString().slice(0, 8);
}

export default function Home() {
  const [active, setActive] = useState("hash");
  const [log, setLog] = useState([]);

  const pushLog = useCallback((tool, message) => {
    setLog((prev) => [...prev.slice(-40), { time: timestamp(), tool, message }]);
  }, []);

  const ActiveComponent = TOOLS.find((t) => t.id === active).component;

  return (
    <main style={{ minHeight: "100vh", display: "flex", flexDirection: "column" }}>
      {/* top bar */}
      <header
        style={{
          borderBottom: "1px solid var(--line)",
          padding: "16px 28px",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
          <div
            style={{
              width: 9,
              height: 9,
              borderRadius: "50%",
              background: "var(--amber)",
              boxShadow: "0 0 10px var(--amber)",
            }}
          />
          <span style={{ fontFamily: "var(--font-display)", fontWeight: 700, fontSize: "17px", letterSpacing: "-0.01em" }}>
            TripWire4
          </span>
        </div>
        <span className="mono" style={{ fontSize: "11px", color: "var(--ink-faint)" }}>
          four utilities · zero telemetry
        </span>
      </header>

      {/* hero */}
      <section style={{ padding: "56px 28px 40px", borderBottom: "1px solid var(--line)" }}>
        <div style={{ maxWidth: "760px" }}>
          <div className="mono" style={{ fontSize: "12px", color: "var(--amber)", marginBottom: "14px", letterSpacing: "0.04em" }}>
            SELF-HOSTED SECURITY UTILITIES
          </div>
          <h1
            style={{
              fontFamily: "var(--font-display)",
              fontSize: "clamp(32px, 5vw, 48px)",
              fontWeight: 700,
              lineHeight: 1.08,
              margin: "0 0 18px",
              letterSpacing: "-0.02em",
            }}
          >
            Four things you'd normally
            <br />
            open four different tabs for.
          </h1>
          <p style={{ fontSize: "15.5px", color: "var(--ink-dim)", lineHeight: 1.65, maxWidth: "580px", margin: 0 }}>
            Identify a hash by its shape. Audit a site's security headers. Catch
            a leaked key before it ships. Check a dependency against a live
            vulnerability database. No accounts, no logging, no data leaving
            this session except the two lookups that need a network round-trip.
          </p>
        </div>
      </section>

      {/* body: tabs + tool */}
      <section style={{ flex: 1, padding: "0 28px", display: "flex", gap: "0" }}>
        <div style={{ width: "100%", maxWidth: "1180px", margin: "0 auto", padding: "36px 0" }}>
          <nav
            style={{
              display: "flex",
              gap: "2px",
              marginBottom: "28px",
              borderBottom: "1px solid var(--line)",
            }}
          >
            {TOOLS.map((t) => (
              <button
                key={t.id}
                onClick={() => setActive(t.id)}
                style={{
                  background: "transparent",
                  border: "none",
                  borderBottom: active === t.id ? "2px solid var(--amber)" : "2px solid transparent",
                  color: active === t.id ? "var(--ink)" : "var(--ink-faint)",
                  padding: "12px 18px",
                  cursor: "pointer",
                  display: "flex",
                  alignItems: "center",
                  gap: "8px",
                  marginBottom: "-1px",
                }}
              >
                <span className="mono" style={{ fontSize: "11px", color: active === t.id ? "var(--amber)" : "var(--ink-faint)" }}>
                  {t.num}
                </span>
                <span style={{ fontFamily: "var(--font-display)", fontSize: "14.5px", fontWeight: 600 }}>
                  {t.label}
                </span>
              </button>
            ))}
          </nav>

          <div style={{ marginBottom: "10px" }}>
            <h2 style={{ fontFamily: "var(--font-display)", fontSize: "22px", fontWeight: 600, margin: "0 0 4px" }}>
              {TOOLS.find((t) => t.id === active).full}
            </h2>
          </div>

          <ActiveComponent log={pushLog} />
        </div>
      </section>

      {/* session log strip */}
      <footer
        style={{
          borderTop: "1px solid var(--line)",
          height: "150px",
          background: "var(--bg-raised)",
        }}
      >
        <div
          className="mono"
          style={{
            fontSize: "10.5px",
            color: "var(--ink-faint)",
            padding: "8px 14px 0",
            textTransform: "uppercase",
            letterSpacing: "0.06em",
          }}
        >
          session log
        </div>
        <div style={{ height: "calc(100% - 24px)" }}>
          <SessionLog entries={log} />
        </div>
      </footer>
    </main>
  );
}
