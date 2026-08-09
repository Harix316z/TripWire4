import "./globals.css";

export const metadata = {
  title: "TripWire4 — Security Utility Toolkit",
  description:
    "Four self-hosted security utilities: hash identification, HTTP header auditing, secret scanning, and dependency vulnerability lookup.",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
