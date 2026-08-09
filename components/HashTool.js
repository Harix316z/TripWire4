"use client";

import { useState } from "react";
import { identifyHash } from "@/lib/hashIdentifier";
import { Panel, Badge, Button, Field, inputStyle } from "./ui";

const SAMPLE = "5f4dcc3b5aa765d61d8327deb882cf99";

export default function HashTool({ log }) {
  const [value, setValue] = useState("");
  const [result, setResult] = useState(null);

  function run(input) {
    const v = input !== undefined ? input : value;
    if (!v.trim()) return;
    const r = identifyHash(v);
    setResult(r);
    log("hash.identify", `${r.matches.length} candidate${r.matches.length === 1 ? "" : "s"} for ${v.length}-char input`);
  }

  return (
    <div style={{ display: "grid", gridTemplateColumns: "minmax(0,1fr) minmax(0,1.1fr)", gap: "22px" }}>
      <div>
        <p style={{ color: "var(--ink-dim)", fontSize: "14px", lineHeight: 1.6, marginTop: 0 }}>
          Fingerprints a hash or token by length, character set, and structural
          prefix. Digests of equal length (MD5/NTLM, SHA-256/SHA3-256) are
          flagged as co-candidates rather than false-resolved.
        </p>
        <Field label="Hash or token">
          <textarea
            value={value}
            onChange={(e) => setValue(e.target.value)}
            placeholder="Paste a hash, PHC string, or token…"
            rows={4}
            style={{ ...inputStyle, resize: "vertical" }}
          />
        </Field>
        <div style={{ display: "flex", gap: "10px" }}>
          <Button onClick={() => run()} disabled={!value.trim()}>
            identify →
          </Button>
          <Button
            variant="ghost"
            onClick={() => {
              setValue(SAMPLE);
              run(SAMPLE);
            }}
          >
            load sample
          </Button>
        </div>
      </div>

      <Panel style={{ padding: "18px", minHeight: "260px" }}>
        {!result && (
          <div style={{ color: "var(--ink-faint)", fontSize: "13px", fontFamily: "var(--font-mono)" }}>
            awaiting input…
          </div>
        )}
        {result && (
          <div>
            <div
              className="mono"
              style={{
                display: "flex",
                justifyContent: "space-between",
                fontSize: "12px",
                color: "var(--ink-faint)",
                marginBottom: "14px",
                paddingBottom: "12px",
                borderBottom: "1px solid var(--line-soft)",
              }}
            >
              <span>len {result.stats.length}</span>
              <span>{result.stats.charset}</span>
              <span>entropy {result.stats.entropy} bits/char</span>
            </div>

            {result.matches.length === 0 && (
              <div style={{ fontSize: "13px", color: "var(--ink-dim)" }}>
                No known family matched this exact length/charset combination.
                Could be a custom digest, ciphertext, or truncated hash.
              </div>
            )}

            {result.matches.map((m) => (
              <div
                key={m.id}
                style={{
                  padding: "12px 0",
                  borderBottom: "1px solid var(--line-soft)",
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "6px" }}>
                  <span style={{ fontFamily: "var(--font-display)", fontWeight: 600, fontSize: "15px" }}>
                    {m.name}
                  </span>
                  <Badge tone={m.confidence === "high" ? "ok" : m.confidence === "medium" ? "medium" : "default"}>
                    {m.confidence} confidence
                  </Badge>
                  <Badge>{m.category}</Badge>
                </div>
                <div style={{ fontSize: "12.5px", color: "var(--ink-dim)", lineHeight: 1.5 }}>{m.note}</div>
              </div>
            ))}
          </div>
        )}
      </Panel>
    </div>
  );
}
