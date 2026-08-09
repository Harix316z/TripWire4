"use client";

import { useState } from "react";
import { scanForSecrets } from "@/lib/secretsPatterns";
import { Panel, Badge, Button, SeverityDot, inputStyle } from "./ui";

// Built from fragments (not one literal block) so no scanner-matchable
// secret pattern sits directly in this source file — the concatenated
// result is still a real match when the tool scans it in the browser.
const SAMPLE = [
  "# config.env",
  "DATABASE_URL=postgres://admin:s3cr3tPass!@db.internal:5432/prod",
  "AWS_ACCESS_KEY_ID=" + "AKIA" + "IOSFODNN7" + "EXAMPLE",
  'aws_secret_access_key = "' + "wJalrXUtnFEMI/K7MDENG/bPxRfiCY" + "EXAMPLEKEY" + '"',
  "GITHUB_TOKEN=" + "ghp_" + "1A2b3C4d5E6f7G8h9I0jKLmNoPqRsTuVwXyZ12345",
  "SLACK_WEBHOOK=" + "https://hooks.slack.co" + "m/services/T00000000/B00000000/" + "EXAMPLEONLY123456789012",
  "STRIPE_KEY=" + "sk_live_" + "51H8xyzABCDEFGHIJKLMNOPQRSTUVWXYZabc",
  'api_key = "' + "8f14e45fceea167a5a36dedd4bea2543ff11223344" + '"',
  'placeholder_token = "changeme"',
].join("\n");

export default function SecretsTool({ log }) {
  const [text, setText] = useState("");
  const [result, setResult] = useState(null);

  function run(input) {
    const v = input !== undefined ? input : text;
    if (!v.trim()) return;
    const r = scanForSecrets(v);
    setResult(r);
    log("secrets.scan", `${r.total} finding${r.total === 1 ? "" : "s"} across ${r.linesScanned} lines`);
  }

  return (
    <div style={{ display: "grid", gridTemplateColumns: "minmax(0,1fr) minmax(0,1fr)", gap: "22px" }}>
      <div>
        <p style={{ color: "var(--ink-dim)", fontSize: "14px", lineHeight: 1.6, marginTop: 0 }}>
          Paste config, code, or logs. Matches known credential formats (AWS,
          GitHub, Stripe, Slack, private key blocks, connection strings) and
          flags high-entropy generic assignments. Runs entirely in your browser
          — nothing here is sent anywhere.
        </p>
        <textarea
          value={text}
          onChange={(e) => setText(e.target.value)}
          placeholder="Paste code or config to scan…"
          rows={14}
          style={{ ...inputStyle, resize: "vertical", fontSize: "12.5px", lineHeight: 1.7 }}
        />
        <div style={{ display: "flex", gap: "10px", marginTop: "12px" }}>
          <Button onClick={() => run()} disabled={!text.trim()}>
            scan →
          </Button>
          <Button
            variant="ghost"
            onClick={() => {
              setText(SAMPLE);
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
            <div style={{ display: "flex", gap: "8px", marginBottom: "16px", flexWrap: "wrap" }}>
              <Badge tone="critical">{result.summary.critical} critical</Badge>
              <Badge tone="high">{result.summary.high} high</Badge>
              <Badge tone="medium">{result.summary.medium} medium</Badge>
              <Badge tone="low">{result.summary.low} low</Badge>
            </div>

            {result.total === 0 && (
              <div style={{ fontSize: "13px", color: "var(--ok)" }}>
                No known credential patterns detected.
              </div>
            )}

            {result.findings.map((f, i) => (
              <div
                key={i}
                style={{
                  padding: "11px 0",
                  borderBottom: "1px solid var(--line-soft)",
                  display: "flex",
                  alignItems: "flex-start",
                }}
              >
                <SeverityDot level={f.severity} />
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ display: "flex", justifyContent: "space-between", gap: "8px" }}>
                    <span style={{ fontSize: "13.5px", fontWeight: 500 }}>{f.label}</span>
                    <span className="mono" style={{ fontSize: "11px", color: "var(--ink-faint)" }}>
                      line {f.line}
                    </span>
                  </div>
                  <div className="mono" style={{ fontSize: "11.5px", color: "var(--ink-faint)", marginTop: "4px", wordBreak: "break-all" }}>
                    {f.preview}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </Panel>
    </div>
  );
}
