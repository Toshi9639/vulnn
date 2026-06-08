import Link from "next/link";

export default function HomePage() {
  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-800">
      {/* Navigation */}
      <nav className="border-b border-slate-800 bg-slate-950/50 backdrop-blur-sm">
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="h-8 w-8 rounded-lg bg-gradient-to-br from-red-500 to-orange-600 flex items-center justify-center">
              <span className="text-white font-bold text-sm">VC</span>
            </div>
            <span className="text-white font-semibold text-lg">VulnCenter</span>
          </div>
          <div className="flex items-center gap-4">
            <Link
              href="/login"
              className="text-slate-400 hover:text-white transition-colors text-sm font-medium"
            >
              Sign In
            </Link>
            <Link
              href="/register"
              className="bg-white text-slate-950 px-4 py-2 rounded-lg text-sm font-medium hover:bg-slate-200 transition-colors"
            >
              Get Started
            </Link>
          </div>
        </div>
      </nav>

      {/* Hero */}
      <section className="max-w-7xl mx-auto px-6 pt-24 pb-16">
        <div className="text-center max-w-3xl mx-auto">
          <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full bg-red-500/10 border border-red-500/20 text-red-400 text-sm font-medium mb-6">
            <span className="h-2 w-2 rounded-full bg-red-500 animate-pulse" />
            Built for Managed Service Providers
          </div>
          <h1 className="text-5xl font-bold text-white leading-tight mb-6">
            Enterprise-Grade Vulnerability Scanning
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-red-400 to-orange-400">
              {" "}for MSPs
            </span>
          </h1>
          <p className="text-lg text-slate-400 leading-relaxed mb-10">
            Manage vulnerability scans for all your clients from a single,
            multi-tenant platform. Automate network scanning, CVE detection,
            and compliance reporting — all self-hosted and fully under your control.
          </p>
          <div className="flex items-center justify-center gap-4">
            <Link
              href="/register"
              className="bg-white text-slate-950 px-8 py-3 rounded-lg font-semibold hover:bg-slate-200 transition-colors"
            >
              Start Free Trial
            </Link>
            <Link
              href="/docs"
              className="border border-slate-700 text-slate-300 px-8 py-3 rounded-lg font-medium hover:border-slate-500 transition-colors"
            >
              View Documentation
            </Link>
          </div>
        </div>
      </section>

      {/* Feature Cards */}
      <section className="max-w-7xl mx-auto px-6 pb-24">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <FeatureCard
            icon="🛡️"
            title="Multi-Tenant Security"
            description="Complete data isolation between clients. Role-based access control with SuperAdmin, ClientAdmin, and Viewer roles."
          />
          <FeatureCard
            icon="🔍"
            title="Automated Scanning"
            description="Integrated Nmap, Nuclei, Nikto, and TestSSL engines. Schedule recurring scans and get real-time notifications on critical findings."
          />
          <FeatureCard
            icon="📊"
            title="Client Reporting"
            description="Generate professional PDF reports with severity breakdowns. Customizable templates for weekly, monthly, or on-demand reports."
          />
        </div>
      </section>

      {/* Tools */}
      <section className="max-w-7xl mx-auto px-6 pb-24">
        <div className="border border-slate-800 rounded-2xl bg-slate-900/50 p-12">
          <h2 className="text-2xl font-bold text-white text-center mb-8">
            Integrated Scanning Engines
          </h2>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-6">
            <ToolCard name="Nmap" description="Port scanning, service detection, OS fingerprinting" />
            <ToolCard name="Nuclei" description="Fast CVE detection with community YAML templates" />
            <ToolCard name="Nikto" description="Web server scanning for OWASP Top 10 vulnerabilities" />
            <ToolCard name="TestSSL" description="SSL/TLS certificate and cipher suite analysis" />
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-slate-800 py-8">
        <div className="max-w-7xl mx-auto px-6 text-center text-slate-500 text-sm">
          VulnCenter — Open Source Vulnerability Scanning Platform for MSPs
        </div>
      </footer>
    </div>
  );
}

function FeatureCard({
  icon,
  title,
  description,
}: {
  icon: string;
  title: string;
  description: string;
}) {
  return (
    <div className="border border-slate-800 rounded-xl bg-slate-900/50 p-8 hover:border-slate-700 transition-colors">
      <div className="text-3xl mb-4">{icon}</div>
      <h3 className="text-white font-semibold text-lg mb-2">{title}</h3>
      <p className="text-slate-400 text-sm leading-relaxed">{description}</p>
    </div>
  );
}

function ToolCard({ name, description }: { name: string; description: string }) {
  return (
    <div className="text-center p-4 rounded-lg bg-slate-800/50 border border-slate-700/50">
      <div className="text-white font-semibold mb-1">{name}</div>
      <div className="text-slate-400 text-xs">{description}</div>
    </div>
  );
}