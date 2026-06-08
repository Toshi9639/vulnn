import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "VulnCenter — Vulnerability Scanning Platform for MSPs",
  description:
    "Multi-tenant vulnerability scanning platform. Manage scans, targets, and reports for all your clients from a single dashboard.",
  keywords: [
    "vulnerability scanning",
    "MSP",
    "security",
    "nmap",
    "nuclei",
    "penetration testing",
  ],
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className={inter.className}>{children}</body>
    </html>
  );
}