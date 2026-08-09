"use client";

import { useState } from "react";
import { Panel, Badge, Button, Field, inputStyle } from "./ui";

const ECOSYSTEMS = ["PyPI", "npm", "Go", "crates.io", "Maven", "RubyGems", "Packagist", "NuGet"];

export default function VulnTool({ log }) {
  const [ecosystem, setEcosystem] = useState("npm");
  const [name, setName] = useState("");
  const [version, setVersion] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  async function run() {
    if (!name.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const res = await fetch("/api/vuln", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ packageName: name, version, ecosystem }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || "Lookup failed.");
        log("vuln.lookup", `failed — ${data.error || "unknown error"}`);
      } else {
        setResult(data);
        log("vuln.lookup", `${ecosystem}/${name}${version ? "@" + version : ""} → ${data.total} advisories`);
      }
    } catch (e) {
      setError("Network error reaching the OSV lookup endpoint.");
    } finally {
      setLoading(false);
    }
  }

  const sevTone = (s) => {
    const v = String(s).toUpperCase();
    if (v.includes("CRIT")) return "critical";
    if (v.includes("HIGH")) return "high";
    if (v.includes("MOD") || v.includes("MED")) return "medium";
    if (v.includes("LOW")) return "low";
    return "default";
  };

  return (
    <div>
      <p style={{ color: "var(--ink-dim)", fontSize: "14px", lineHeight: 1.6, marginTop: 0, maxWidth: "640px" }}>
        Queries <span className="mono">OSV.dev</span> — the open vulnerability
        database backed by Google/OpenSSF — for known advisories against a
        package name and optional version, across eight ecosystems.
      </p>

      <div style={{ display: "grid", gridTemplateColumns: "140px 1fr 140px auto", gap: "10px", alignItems: "flex-end", maxWidth: "720px", marginBottom: "20px" }}>
        <Field label="Ecosystem">
          <select
            value={ecosystem}
            onChange={(e) => setEcosystem(e.target.value)}
            style={{ ...inputStyle, appearance: "auto" }}
          >
            {ECOSYSTEMS.map((eco) => (
              <option key={eco} value={eco}>
                {eco}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Package name">
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && run()}
            placeholder="e.g. lodash, requests, express"
            style={inputStyle}
          />
        </Field>
        <Field label="Version (optional)">
          <input
            value={version}
            onChange={(e) => setVersion(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && run()}
            placeholder="4.17.15"
            style={inputStyle}
          />
        </Field>
        <Button onClick={run} disabled={loading || !name.trim()} style={{ marginBottom: "14px" }}>
          {loading ? "querying…" : "lookup →"}
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
        <Panel style={{ padding: "6px 0" }}>
          <div
            style={{
              padding: "13px 18px",
              borderBottom: "1px solid var(--line-soft)",
              display: "flex",
              justifyContent: "space-between",
              fontSize: "12px",
            }}
            className="mono"
          >
            <span style={{ color: "var(--ink-dim)" }}>
              {result.ecosystem}/{result.packageName}
              {result.version ? `@${result.version}` : ""}
            </span>
            <span style={{ color: result.total > 0 ? "var(--high)" : "var(--ok)" }}>
              {result.total} advisor{result.total === 1 ? "y" : "ies"}
            </span>
          </div>

          {result.total === 0 && (
            <div style={{ padding: "18px", fontSize: "13px", color: "var(--ok)" }}>
              No known advisories for this {result.version ? "version" : "package"} in OSV.dev.
            </div>
          )}

          {result.vulns.map((v, i) => (
            <div
              key={v.id}
              style={{
                padding: "14px 18px",
                borderBottom: i < result.vulns.length - 1 ? "1px solid var(--line-soft)" : "none",
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "6px", flexWrap: "wrap" }}>
                <span className="mono" style={{ fontSize: "13px", fontWeight: 600, color: "var(--amber)" }}>
                  {v.id}
                </span>
                <Badge tone={sevTone(v.severity)}>{v.severity}</Badge>
                {v.published && (
                  <span className="mono" style={{ fontSize: "11px", color: "var(--ink-faint)" }}>
                    published {v.published.slice(0, 10)}
                  </span>
                )}
              </div>
              <div style={{ fontSize: "13px", color: "var(--ink-dim)", lineHeight: 1.5, marginBottom: "6px" }}>
                {v.summary}
              </div>
              {v.fixedVersions.length > 0 && (
                <div className="mono" style={{ fontSize: "11.5px", color: "var(--ok)" }}>
                  fixed in: {v.fixedVersions.join(", ")}
                </div>
              )}
            </div>
          ))}
        </Panel>
      )}
    </div>
  );
}
