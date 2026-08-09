"use client";

import { useEffect, useRef } from "react";

export default function SessionLog({ entries }) {
  const scrollRef = useRef(null);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [entries]);

  return (
    <div
      ref={scrollRef}
      className="mono"
      style={{
        height: "100%",
        overflowY: "auto",
        padding: "10px 14px",
        fontSize: "12px",
        lineHeight: "1.9",
        color: "var(--ink-faint)",
      }}
    >
      {entries.length === 0 && (
        <div style={{ color: "var(--ink-faint)" }}>
          session idle — run a tool to populate the log
        </div>
      )}
      {entries.map((e, i) => (
        <div key={i} style={{ whiteSpace: "nowrap" }}>
          <span style={{ color: "var(--ink-faint)" }}>{e.time}</span>{" "}
          <span style={{ color: "var(--amber-dim)" }}>{e.tool}</span>{" "}
          <span style={{ color: "var(--ink-dim)" }}>{e.message}</span>
        </div>
      ))}
    </div>
  );
}
