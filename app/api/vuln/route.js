import { NextResponse } from "next/server";

// Queries OSV.dev (osv.dev) - a free, no-auth-required open vulnerability
// database maintained by Google/OpenSSF that indexes advisories from GitHub,
// PyPA, RustSec, Go vuln DB, npm, and more.
const OSV_ENDPOINT = "https://api.osv.dev/v1/query";

const ECOSYSTEMS = ["PyPI", "npm", "Go", "crates.io", "Maven", "RubyGems", "Packagist", "NuGet"];

export async function POST(req) {
  let body;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Malformed request body." }, { status: 400 });
  }

  const { packageName, version, ecosystem } = body || {};
  if (!packageName || typeof packageName !== "string") {
    return NextResponse.json({ error: "Provide a 'packageName' field." }, { status: 400 });
  }
  if (!ecosystem || !ECOSYSTEMS.includes(ecosystem)) {
    return NextResponse.json(
      { error: `Provide an 'ecosystem' field, one of: ${ECOSYSTEMS.join(", ")}` },
      { status: 400 }
    );
  }

  const query = {
    package: { name: packageName.trim(), ecosystem },
  };
  if (version && typeof version === "string" && version.trim()) {
    query.version = version.trim();
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 8000);

  let res;
  try {
    res = await fetch(OSV_ENDPOINT, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(query),
      signal: controller.signal,
    });
  } catch (err) {
    clearTimeout(timeout);
    return NextResponse.json(
      { error: err.name === "AbortError" ? "OSV.dev request timed out." : "Couldn't reach OSV.dev." },
      { status: 502 }
    );
  }
  clearTimeout(timeout);

  if (!res.ok) {
    return NextResponse.json({ error: `OSV.dev returned ${res.status}.` }, { status: 502 });
  }

  const data = await res.json();
  const vulns = (data.vulns || []).map((v) => {
    const severity =
      v.severity?.[0]?.score ||
      v.database_specific?.severity ||
      inferSeverityFromAliases(v) ||
      "UNKNOWN";

    const fixedVersions = extractFixedVersions(v);

    return {
      id: v.id,
      summary: v.summary || v.details?.slice(0, 200) || "No summary provided.",
      aliases: v.aliases || [],
      severity,
      published: v.published || null,
      fixedVersions,
      references: (v.references || []).slice(0, 3).map((r) => r.url),
    };
  });

  return NextResponse.json({
    packageName: packageName.trim(),
    ecosystem,
    version: version?.trim() || null,
    total: vulns.length,
    vulns,
  });
}

function inferSeverityFromAliases(v) {
  const text = JSON.stringify(v).toUpperCase();
  if (text.includes("CRITICAL")) return "CRITICAL";
  if (text.includes("HIGH")) return "HIGH";
  if (text.includes("MODERATE") || text.includes("MEDIUM")) return "MODERATE";
  if (text.includes("LOW")) return "LOW";
  return null;
}

function extractFixedVersions(v) {
  const fixed = new Set();
  for (const affected of v.affected || []) {
    for (const range of affected.ranges || []) {
      for (const event of range.events || []) {
        if (event.fixed) fixed.add(event.fixed);
      }
    }
  }
  return Array.from(fixed).slice(0, 5);
}

export async function GET() {
  return NextResponse.json({ ecosystems: ECOSYSTEMS });
}
