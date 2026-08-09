// Regex signatures for common leaked-credential formats, plus a Shannon
// entropy fallback for generic high-entropy strings assigned to suspicious
// variable names (api_key = "...", token: "...", etc).

const SIGNATURES = [
  { id: "aws-access-key", label: "AWS Access Key ID", severity: "critical", re: /\bAKIA[0-9A-Z]{16}\b/g },
  { id: "aws-secret-key", label: "AWS Secret Access Key (heuristic)", severity: "critical", re: /\b(?:aws_secret_access_key|aws_secret)\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?/gi },
  { id: "github-token", label: "GitHub Token", severity: "critical", re: /\bgh[pousr]_[A-Za-z0-9]{36,255}\b/g },
  { id: "github-fine-grained", label: "GitHub Fine-Grained PAT", severity: "critical", re: /\bgithub_pat_[A-Za-z0-9_]{22,255}\b/g },
  { id: "slack-token", label: "Slack Token", severity: "high", re: /\bxox[baprs]-[A-Za-z0-9-]{10,72}\b/g },
  { id: "slack-webhook", label: "Slack Webhook URL", severity: "medium", re: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/]+/g },
  { id: "stripe-key", label: "Stripe API Key", severity: "critical", re: /\b(?:sk|pk|rk)_(live|test)_[A-Za-z0-9]{16,247}\b/g },
  { id: "google-api-key", label: "Google API Key", severity: "high", re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { id: "google-oauth", label: "Google OAuth Client Secret", severity: "high", re: /\bGOCSPX-[A-Za-z0-9_-]{20,}\b/g },
  { id: "private-key-block", label: "Private Key Block (PEM)", severity: "critical", re: /-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g },
  { id: "npm-token", label: "npm Access Token", severity: "high", re: /\bnpm_[A-Za-z0-9]{36}\b/g },
  { id: "twilio-key", label: "Twilio API Key", severity: "high", re: /\bSK[a-f0-9]{32}\b/g },
  { id: "sendgrid-key", label: "SendGrid API Key", severity: "high", re: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g },
  { id: "mailgun-key", label: "Mailgun API Key", severity: "medium", re: /\bkey-[a-f0-9]{32}\b/g },
  { id: "heroku-key", label: "Heroku API Key (UUID heuristic)", severity: "medium", re: /\bheroku[a-z_]*\s*[:=]\s*["']?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}["']?/gi },
  { id: "jwt", label: "JWT (JSON Web Token)", severity: "medium", re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g },
  { id: "generic-basic-auth", label: "Basic Auth Credentials in URL", severity: "high", re: /\b[a-z][a-z0-9+.-]*:\/\/[^\s:/@]+:[^\s:/@]+@[^\s]+/gi },
  { id: "db-conn-string", label: "Database Connection String", severity: "high", re: /\b(postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis):\/\/[^\s"'<>]+/gi },
  {
    id: "generic-secret-assignment",
    label: "Generic Secret Assignment",
    severity: "medium",
    re: /\b(?:api[_-]?key|apikey|secret|token|auth[_-]?token|access[_-]?key|client[_-]?secret|password|passwd|pwd)\s*[:=]\s*["']([A-Za-z0-9_\-/+=]{12,})["']/gi,
  },
];

function shannonEntropy(str) {
  const freq = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  let entropy = 0;
  for (const ch in freq) {
    const p = freq[ch] / str.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function lineNumberAt(text, index) {
  return text.slice(0, index).split("\n").length;
}

function redact(value) {
  if (value.length <= 8) return "*".repeat(value.length);
  return value.slice(0, 4) + "*".repeat(Math.max(4, value.length - 8)) + value.slice(-4);
}

export function scanForSecrets(text) {
  const findings = [];
  const seen = new Set();

  for (const sig of SIGNATURES) {
    let match;
    const re = new RegExp(sig.re.source, sig.re.flags);
    while ((match = re.exec(text)) !== null) {
      const value = match[1] || match[0];
      const key = sig.id + ":" + match.index;
      if (seen.has(key)) continue;
      seen.add(key);

      // Suppress obvious placeholders / low-entropy noise for the generic rule.
      if (sig.id === "generic-secret-assignment") {
        const ent = shannonEntropy(value);
        if (ent < 3.2) continue;
        if (/^(x+|0+|1+|change[_-]?me|your[_-]?key|placeholder|example|dummy|test)$/i.test(value)) continue;
      }

      findings.push({
        id: sig.id,
        label: sig.label,
        severity: sig.severity,
        line: lineNumberAt(text, match.index),
        preview: redact(match[0].trim()),
        entropy: Number(shannonEntropy(value).toFixed(2)),
      });

      if (match.index === re.lastIndex) re.lastIndex++;
    }
  }

  findings.sort((a, b) => a.line - b.line);

  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
  findings.forEach((f) => bySeverity[f.severity]++);

  return {
    findings: findings.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]),
    summary: bySeverity,
    linesScanned: text.split("\n").length,
    total: findings.length,
  };
}
