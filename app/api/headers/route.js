import { NextResponse } from "next/server";

// Security-relevant response headers, their weight in the score, and the
// guidance shown when they're missing or misconfigured.
const CHECKS = [
  {
    key: "strict-transport-security",
    label: "Strict-Transport-Security",
    weight: 20,
    guidance: "Forces browsers to use HTTPS for future requests. Missing this allows protocol-downgrade attacks.",
  },
  {
    key: "content-security-policy",
    label: "Content-Security-Policy",
    weight: 25,
    guidance: "Restricts which sources scripts, styles, and frames can load from. The single strongest defense against XSS.",
  },
  {
    key: "x-content-type-options",
    label: "X-Content-Type-Options",
    weight: 10,
    guidance: "Should be 'nosniff'. Prevents browsers from MIME-sniffing a response away from its declared content type.",
  },
  {
    key: "x-frame-options",
    label: "X-Frame-Options",
    weight: 15,
    guidance: "Should be 'DENY' or 'SAMEORIGIN'. Prevents clickjacking via iframe embedding (superseded by CSP frame-ancestors, but still widely checked).",
  },
  {
    key: "referrer-policy",
    label: "Referrer-Policy",
    weight: 10,
    guidance: "Controls how much referrer info leaks to other origins on navigation. 'strict-origin-when-cross-origin' is a safe default.",
  },
  {
    key: "permissions-policy",
    label: "Permissions-Policy",
    weight: 10,
    guidance: "Explicitly disables powerful browser features (camera, mic, geolocation) that the page doesn't use.",
  },
  {
    key: "cross-origin-opener-policy",
    label: "Cross-Origin-Opener-Policy",
    weight: 5,
    guidance: "Isolates the browsing context from cross-origin windows, mitigating Spectre-class and tab-nabbing attacks.",
  },
  {
    key: "cross-origin-resource-policy",
    label: "Cross-Origin-Resource-Policy",
    weight: 5,
    guidance: "Blocks other origins from loading this resource unless explicitly allowed.",
  },
];

function normalizeUrl(input) {
  let url = input.trim();
  if (!/^https?:\/\//i.test(url)) url = "https://" + url;
  return url;
}

export async function POST(req) {
  let body;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Malformed request body." }, { status: 400 });
  }

  const target = body?.url;
  if (!target || typeof target !== "string") {
    return NextResponse.json({ error: "Provide a 'url' field." }, { status: 400 });
  }

  const url = normalizeUrl(target);
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return NextResponse.json({ error: "That doesn't look like a valid URL." }, { status: 400 });
  }
  if (!["http:", "https:"].includes(parsed.protocol)) {
    return NextResponse.json({ error: "Only http(s) targets are supported." }, { status: 400 });
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 8000);

  let res;
  let usedMethod = "GET";
  try {
    res = await fetch(parsed.toString(), {
      method: "GET",
      redirect: "follow",
      signal: controller.signal,
      headers: { "User-Agent": "recon-console-header-scanner/1.0" },
    });
  } catch (err) {
    clearTimeout(timeout);
    return NextResponse.json(
      { error: `Couldn't reach that host: ${err.name === "AbortError" ? "request timed out" : "connection failed"}.` },
      { status: 502 }
    );
  }
  clearTimeout(timeout);

  const headers = {};
  res.headers.forEach((value, key) => {
    headers[key.toLowerCase()] = value;
  });

  let earned = 0;
  const total = CHECKS.reduce((sum, c) => sum + c.weight, 0);
  const results = CHECKS.map((check) => {
    const present = Boolean(headers[check.key]);
    if (present) earned += check.weight;
    return {
      key: check.key,
      label: check.label,
      present,
      value: headers[check.key] || null,
      guidance: check.guidance,
      weight: check.weight,
    };
  });

  const serverHeader = headers["server"] || null;
  const poweredBy = headers["x-powered-by"] || null;

  return NextResponse.json({
    url: parsed.toString(),
    status: res.status,
    method: usedMethod,
    score: Math.round((earned / total) * 100),
    results,
    disclosures: {
      server: serverHeader,
      poweredBy: poweredBy,
    },
  });
}
