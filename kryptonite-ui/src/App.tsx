import { useState, useRef, useEffect } from "react";

interface Finding {
  id: string;
  title: string;
  description: string;
  severity: string;
  owasp_category: string;
  evidence: Array<{
    file: string;
    line?: number;
    snippet: string;
  }>;
  remediation: string;
}

interface Report {
  meta: {
    tool: string;
    version: string;
    scan_date: string;
  };
  app_info: {
    name: string;
    bundle_id: string;
    version: string;
    platform: string;
  };
  summary: {
    total_findings: number;
    severity_breakdown: {
      Critical: number;
      High: number;
      Medium: number;
      Low: number;
      Info: number;
    };
    risk_score: number;
    risk_label: string;
  };
  owasp_mapping: any[];
  findings: Finding[];
}

function App() {
  const [file, setFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState<Report | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const [theme, setTheme] = useState<"light" | "dark">("light");
  const [activeTab, setActiveTab] = useState<string>("All");
  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const storedTheme = localStorage.getItem("kryptonite-theme");
    if (storedTheme === "light" || storedTheme === "dark") {
      setTheme(storedTheme);
      return;
    }
    const prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
    setTheme(prefersDark ? "dark" : "light");
  }, []);

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("kryptonite-theme", theme);
  }, [theme]);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFile = e.target.files?.[0];
    if (selectedFile) {
      setFile(selectedFile);
      setError(null);
      setReport(null);
    }
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    const droppedFile = e.dataTransfer.files[0];
    if (droppedFile && (droppedFile.name.endsWith('.apk') || droppedFile.name.endsWith('.ipa'))) {
      setFile(droppedFile);
      setError(null);
      setReport(null);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!file) return;

    setLoading(true);
    setError(null);

    const formData = new FormData();
    formData.append("file", file);

    try {
      const response = await fetch("https://cool-starfish-suitable.ngrok-free.app/analyze", {
        method: "POST",
        body: formData,
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || "Analysis failed");
      }

      const data: Report = await response.json();
      setReport(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "An error occurred");
    } finally {
      setLoading(false);
    }
  };

  const getSeverityBadgeClass = (severity: string) => {
    switch (severity.toLowerCase()) {
      case "critical":
        return "badge badge-critical";
      case "high":
        return "badge badge-high";
      case "medium":
        return "badge badge-medium";
      case "low":
        return "badge badge-low";
      case "info":
        return "badge badge-info";
      default:
        return "badge badge-info";
    }
  };

  const getOwaspCategories = (findings: Finding[]) => {
    const categories = new Set<string>();
    findings.forEach(f => {
      const match = f.owasp_category.match(/M(\d+)/);
      if (match) {
        categories.add(`M${match[1]}`);
      }
    });
    return Array.from(categories).sort((a, b) => {
      const numA = parseInt(a.substring(1));
      const numB = parseInt(b.substring(1));
      return numA - numB;
    });
  };

  const filterFindingsByTab = (findings: Finding[], tab: string) => {
    if (tab === "All") return findings;
    return findings.filter(f => f.owasp_category.includes(tab));
  };

  return (
    <div className="page">
      <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-12 space-y-6">
        <header className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mb-4">
          <div>
            <h1 className="text-4xl sm:text-5xl font-bold tracking-tight">Kryptonite</h1>
            <p className="subtle mt-2 text-base">Advanced mobile static analysis security tool</p>
          </div>
          <button
            type="button"
            className="button button-secondary flex items-center gap-2"
            onClick={() => setTheme(theme === "light" ? "dark" : "light")}
          >
            {theme === "light" ? (
              <>
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z" />
                </svg>
                <span>Dark</span>
              </>
            ) : (
              <>
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z" />
                </svg>
                <span>Light</span>
              </>
            )}
          </button>
        </header>

        <section className="card card-elevated p-8">
          <form onSubmit={handleSubmit} className="space-y-5">
            <div
              onDragOver={handleDragOver}
              onDragLeave={handleDragLeave}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current?.click()}
              className={`dropzone ${isDragging ? "drag" : ""}`}
            >
              <input
                ref={fileInputRef}
                type="file"
                id="file"
                accept=".apk,.ipa"
                onChange={handleFileChange}
                className="hidden"
              />

              <div className="flex flex-col items-center gap-3 text-center">
                {file ? (
                  <>
                    <div className="w-14 h-14 rounded-xl bg-gradient-to-br from-slate-100 to-slate-200 dark:from-slate-700 dark:to-slate-800 flex items-center justify-center">
                      <svg className="w-8 h-8 subtle" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                      </svg>
                    </div>
                    <div>
                      <p className="text-base font-semibold">{file.name}</p>
                      <p className="subtle text-sm mt-1">{(file.size / 1024 / 1024).toFixed(2)} MB</p>
                    </div>
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        setFile(null);
                      }}
                      className="button button-secondary text-sm mt-1"
                    >
                      Choose another file
                    </button>
                  </>
                ) : (
                  <>
                    <div className="w-14 h-14 rounded-xl bg-gradient-to-br from-slate-100 to-slate-200 dark:from-slate-700 dark:to-slate-800 flex items-center justify-center">
                      <svg className="w-8 h-8 subtle" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
                      </svg>
                    </div>
                    <div>
                      <p className="text-lg font-semibold">Drop your file here or click to browse</p>
                      <p className="subtle text-sm mt-1">Supports APK and IPA files</p>
                    </div>
                  </>
                )}
              </div>
            </div>

            <button
              type="submit"
              disabled={!file || loading}
              className="button button-primary w-full py-3"
            >
              {loading ? "Analyzing…" : "Analyze file"}
            </button>
          </form>
        </section>

        {loading && (
          <div className="card card-elevated p-6 flex items-center gap-4">
            <span className="loader" aria-hidden="true" />
            <div>
              <p className="font-semibold">Analyzing file</p>
              <p className="subtle text-sm mt-1">This can take a moment. Please wait…</p>
            </div>
          </div>
        )}

        {/* Error Message */}
        {error && (
          <div className="card card-elevated p-5 border-l-4 border-l-red-500">
            <div className="flex items-start gap-3">
              <svg className="w-5 h-5 text-red-500 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              <div>
                <p className="font-semibold text-red-600">Error</p>
                <p className="text-sm subtle mt-1">{error}</p>
              </div>
            </div>
          </div>
        )}

        {/* Report */}
        {report && (
          <div className="space-y-8">
            <section className="card card-elevated p-8">
              <h2 className="section-title mb-5">App information</h2>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                {[
                  { label: "Name", value: report.app_info.name, icon: "📱" },
                  { label: "Bundle ID", value: report.app_info.bundle_id, icon: "🔖" },
                  { label: "Version", value: report.app_info.version, icon: "📦" },
                  { label: "Platform", value: report.app_info.platform, icon: "⚙️" }
                ].map((item, idx) => (
                  <div key={idx} className="info-card">
                    <div className="flex items-center gap-2 mb-2">
                      <span className="text-xl">{item.icon}</span>
                      <p className="label">{item.label}</p>
                    </div>
                    <p className="value text-base truncate" title={item.value}>{item.value}</p>
                  </div>
                ))}
              </div>
            </section>

            <section className="card card-elevated p-8">
              <h2 className="section-title mb-5">Security summary</h2>
              
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
                {/* Severity Chart */}
                <div>
                  <p className="label mb-4">Severity distribution</p>
                  <div className="space-y-3">
                    {[
                      { label: "Critical", count: report.summary.severity_breakdown.Critical || 0, color: "bg-red-500" },
                      { label: "High", count: report.summary.severity_breakdown.High || 0, color: "bg-orange-500" },
                      { label: "Medium", count: report.summary.severity_breakdown.Medium || 0, color: "bg-yellow-500" },
                      { label: "Low", count: report.summary.severity_breakdown.Low || 0, color: "bg-green-500" },
                      { label: "Info", count: report.summary.severity_breakdown.Info || 0, color: "bg-slate-400" }
                    ].map((item, idx) => {
                      const maxCount = Math.max(
                        report.summary.severity_breakdown.Critical || 0,
                        report.summary.severity_breakdown.High || 0,
                        report.summary.severity_breakdown.Medium || 0,
                        report.summary.severity_breakdown.Low || 0,
                        report.summary.severity_breakdown.Info || 0,
                        1
                      );
                      const percentage = (item.count / maxCount) * 100;
                      return (
                        <div key={idx} className="flex items-center gap-3">
                          <div className="w-20 text-sm font-medium">{item.label}</div>
                          <div className="flex-1 h-8 bg-slate-100 dark:bg-slate-800 rounded-lg overflow-hidden">
                            <div
                              className={`h-full ${item.color} transition-all duration-500 flex items-center justify-end pr-2`}
                              style={{ width: `${percentage}%` }}
                            >
                              {item.count > 0 && (
                                <span className="text-xs font-semibold text-white">{item.count}</span>
                              )}
                            </div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>

                {/* Risk Score Circle */}
                <div className="flex flex-col items-center justify-center">
                  <p className="label mb-4">Risk assessment</p>
                  <div className="relative w-40 h-40">
                    <svg className="transform -rotate-90 w-40 h-40">
                      <circle
                        cx="80"
                        cy="80"
                        r="70"
                        stroke="currentColor"
                        strokeWidth="12"
                        fill="none"
                        className="subtle opacity-20"
                      />
                      <circle
                        cx="80"
                        cy="80"
                        r="70"
                        stroke="currentColor"
                        strokeWidth="12"
                        fill="none"
                        strokeDasharray={`${(report.summary.risk_score / 100) * 439.6} 439.6`}
                        strokeLinecap="round"
                        className="text-red-500"
                      />
                    </svg>
                    <div className="absolute inset-0 flex flex-col items-center justify-center">
                      <span className="text-3xl font-bold">{report.summary.risk_score}</span>
                      <span className="text-xs subtle mt-1">out of 100</span>
                    </div>
                  </div>
                  <p className="value text-lg mt-4">{report.summary.risk_label}</p>
                </div>
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3 mt-6 pt-6 border-t border-border">
                {[
                  { label: "Critical", count: report.summary.severity_breakdown.Critical || 0 },
                  { label: "High", count: report.summary.severity_breakdown.High || 0 },
                  { label: "Medium", count: report.summary.severity_breakdown.Medium || 0 },
                  { label: "Low", count: report.summary.severity_breakdown.Low || 0 },
                  { label: "Total", count: report.summary.total_findings }
                ].map((item, idx) => (
                  <div key={idx} className="stat-compact text-center">
                    <p className="value text-2xl">{item.count}</p>
                    <p className="label text-xs">{item.label}</p>
                  </div>
                ))}
              </div>
            </section>

            <section className="card card-elevated p-8">
              <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mb-6">
                <h2 className="section-title mb-0">Security findings</h2>
                <p className="subtle text-sm">
                  {activeTab === "All" 
                    ? `${report.findings.length} total findings`
                    : `${filterFindingsByTab(report.findings, activeTab).length} findings in ${activeTab}`
                  }
                </p>
              </div>

              {/* Tabs */}
              <div className="flex flex-wrap gap-2 mb-6 pb-4 border-b border-border">
                <button
                  onClick={() => setActiveTab("All")}
                  className={`tab ${activeTab === "All" ? "tab-active" : ""}`}
                >
                  All
                </button>
                {getOwaspCategories(report.findings).map((category) => {
                  const count = report.findings.filter(f => f.owasp_category.includes(category)).length;
                  return (
                    <button
                      key={category}
                      onClick={() => setActiveTab(category)}
                      className={`tab ${activeTab === category ? "tab-active" : ""}`}
                    >
                      {category}
                      <span className="tab-count">{count}</span>
                    </button>
                  );
                })}
              </div>

              {report.findings.length === 0 ? (
                <div className="text-center py-12">
                  <div className="w-16 h-16 rounded-2xl bg-green-100 dark:bg-green-900/20 flex items-center justify-center mx-auto mb-4">
                    <svg className="w-10 h-10 text-green-600 dark:text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                  </div>
                  <p className="value text-xl mb-2">No security issues found</p>
                  <p className="subtle">Your app looks secure!</p>
                </div>
              ) : (
                <div className="space-y-4">
                  {filterFindingsByTab(report.findings, activeTab).length === 0 ? (
                    <div className="text-center py-12">
                      <p className="subtle">No findings in this category</p>
                    </div>
                  ) : (
                    filterFindingsByTab(report.findings, activeTab).map((finding, index) => (
                    <div key={index} className="finding-card">
                      <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-3 mb-3">
                        <h3 className="text-lg font-semibold flex-1">{finding.title}</h3>
                        <span className={getSeverityBadgeClass(finding.severity)}>
                          {finding.severity.toUpperCase()}
                        </span>
                      </div>
                      <p className="subtle mb-4 leading-relaxed">{finding.description}</p>

                      <div className="flex flex-wrap gap-2 mb-4">
                        <span className="badge badge-owasp">
                          <svg className="w-3 h-3 inline mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 7h.01M7 3h5c.512 0 1.024.195 1.414.586l7 7a2 2 0 010 2.828l-7 7a2 2 0 01-2.828 0l-7-7A1.994 1.994 0 013 12V7a4 4 0 014-4z" />
                          </svg>
                          {finding.owasp_category}
                        </span>
                      </div>

                      {finding.remediation && (
                        <div className="remediation-box">
                          <div className="flex items-start gap-2">
                            <svg className="w-5 h-5 text-green-600 dark:text-green-500 mt-0.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                            </svg>
                            <div className="flex-1">
                              <p className="label font-semibold mb-1">Remediation</p>
                              <p className="subtle text-sm leading-relaxed">{finding.remediation}</p>
                            </div>
                          </div>
                        </div>
                      )}

                      {finding.evidence.length > 0 && (
                        <div className="mt-4">
                          <p className="label font-semibold mb-3 flex items-center gap-2">
                            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                            </svg>
                            Evidence ({finding.evidence.length})
                          </p>
                          <div className="space-y-3">
                            {finding.evidence.map((ev, evIndex) => (
                              <div key={evIndex} className="evidence-box">
                                <div className="flex flex-col sm:flex-row sm:items-center gap-2 text-sm mb-2">
                                  <span className="font-mono text-xs subtle truncate" title={ev.file}>{ev.file}</span>
                                  {ev.line && (
                                    <span className="badge badge-line">Line {ev.line}</span>
                                  )}
                                </div>
                                {ev.snippet && (
                                  <pre className="code-block">
                                    <code className="text-xs">{ev.snippet}</code>
                                  </pre>
                                )}
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  )))}
                </div>
              )}
            </section>
          </div>
        )}
      </div>
    </div>
  );
}

export default App;
