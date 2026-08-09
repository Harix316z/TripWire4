"use client";

import { useState } from "react";
import { Panel, Badge, Button, Field, inputStyle } from "./ui";

export default function HeadersTool({ log }) {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  async function run() {
    if (!url.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const res = await fetch("/api/headers", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || "Scan failed.");
        log("headers.scan", `failed — ${data.error || "unknown error"}`);
      } else {
        setResult(data);
        log("headers.scan", `${data.url.replace(/^https?:\/\//, "")} → score ${data.score}/100`);
      }
    } catch (e) {
      setError("Network error reaching the scan endpoint.");
    } finally {
      setLoading(false);
    }
  }

  const scoreColor = (s) => (s >= 80 ? "var(--ok)" : s >= 50 ? "var(--med)" : "var(--crit)");

  return (
    <div>
      <p style={{ color: "var(--ink-dim)", fontSize: "14px", lineHeight: 1.6, marginTop: 0, maxWidth: "640px" }}>
        Fetches a URL server-side and audits its response for eight security-relevant
        headers (CSP, HSTS, framing, MIME-sniffing protection, and origin isolation policies).
      </p>
      <div style={{ display: "flex", gap: "10px", alignItems: "flex-end", marginBottom: "20px", maxWidth: "640px" }}>
        <div style={{ flex: 1 }}>
          <Field label="Target URL">
            <input
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && run()}
              placeholder="example.com"
              style={inputStyle}
            />
          </Field>
        </div>
        <Button onClick={run} disabled={loading || !url.trim()} style={{ marginBottom: "14px" }}>
          {loading ? "scanning…" : "scan →"}
        </Button>
      </div>

      {error && (
        <Panel style={{ padding: "14px 16px", borderColor: "rgba(255,92,92,0.35)", marginBottom: "20px" }}>
          <span className="mono" style={{ color: "var(--crit)", fontSize: "13px" }}>
            {error}
          </span>
        </Panel>
      )}

      {result && (
        <div style={{ display: "grid", gridTemplateColumns: "220px 1fr", gap: "22px" }}>
          <Panel style={{ padding: "20px", textAlign: "center", height: "fit-content" }}>
            <div className="mono" style={{ fontSize: "11px", color: "var(--ink-faint)", textTransform: "uppercase", marginBottom: "10px" }}>
              header score
            </div>
            <div style={{ fontFamily: "var(--font-display)", fontSize: "48px", fontWeight: 700, color: scoreColor(result.score), lineHeight: 1 }}>
              {result.score}
            </div>
            <div className="mono" style={{ fontSize: "12px", color: "var(--ink-faint)", marginTop: "4px" }}>
              / 100
            </div>
            <div style={{ marginTop: "16px", paddingTop: "16px", borderTop: "1px solid var(--line-soft)", textAlign: "left" }}>
              <div className="mono" style={{ fontSize: "11px", color: "var(--ink-faint)", marginBottom: "6px" }}>
                HTTP {result.status}
              </div>
              <div className="mono" style={{ fontSize: "11px", color: "var(--ink-faint)", wordBreak: "break-all" }}>
                {result.url}
              </div>
              {result.disclosures.server && (
                <div className="mono" style={{ fontSize: "11px", color: "var(--high)", marginTop: "8px" }}>
                  server: {result.disclosures.server}
                </div>
              )}
              {result.disclosures.poweredBy && (
                <div className="mono" style={{ fontSize: "11px", color: "var(--high)" }}>
                  x-powered-by: {result.disclosures.poweredBy}
                </div>
              )}
            </div>
          </Panel>

          <Panel style={{ padding: "6px 0" }}>
            {result.results.map((r, i) => (
              <div
                key={r.key}
                style={{
                  padding: "13px 18px",
                  borderBottom: i < result.results.length - 1 ? "1px solid var(--line-soft)" : "none",
                  display: "flex",
                  alignItems: "flex-start",
                  justifyContent: "space-between",
                  gap: "16px",
                }}
              >
                <div>
                  <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "4px" }}>
                    <span className="mono" style={{ fontSize: "13px", fontWeight: 500 }}>
                      {r.label}
                    </span>
                    <Badge tone={r.present ? "ok" : "critical"}>{r.present ? "present" : "missing"}</Badge>
                  </div>
                  <div style={{ fontSize: "12.5px", color: "var(--ink-dim)", lineHeight: 1.5, maxWidth: "520px" }}>
                    {r.guidance}
                  </div>
                  {r.value && (
                    <div className="mono" style={{ fontSize: "11px", color: "var(--ink-faint)", marginTop: "6px", wordBreak: "break-all" }}>
                      {r.value}
                    </div>
                  )}
                </div>
              </div>
            ))}
          </Panel>
        </div>
      )}
    </div>
  );
}
