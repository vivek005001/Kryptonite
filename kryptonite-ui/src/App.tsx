import { useState, useRef } from "react";

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
  const fileInputRef = useRef<HTMLInputElement>(null);

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

  const getSeverityBadgeColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case "critical":
        return "bg-gradient-to-r from-red-500/20 to-pink-600/20 text-red-300 border-red-500/30";
      case "high":
        return "bg-gradient-to-r from-orange-500/20 to-red-500/20 text-orange-300 border-orange-500/30";
      case "medium":
        return "bg-gradient-to-r from-yellow-500/20 to-orange-500/20 text-yellow-300 border-yellow-500/30";
      case "low":
        return "bg-gradient-to-r from-blue-500/20 to-cyan-500/20 text-blue-300 border-blue-500/30";
      case "info":
        return "bg-gradient-to-r from-gray-500/20 to-slate-500/20 text-gray-300 border-gray-500/30";
      default:
        return "bg-gradient-to-r from-gray-500/20 to-slate-500/20 text-gray-300 border-gray-500/30";
    }
  };

  return (
    <div className="min-h-screen py-8 px-4 sm:px-6 lg:px-8">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="text-center mb-12 animate-fade-in">
          <div className="flex items-center justify-center gap-3 mb-4">
            <div className="w-16 h-16 bg-gradient-to-br from-cyan-500 to-purple-600 rounded-2xl flex items-center justify-center shadow-lg shadow-cyan-500/20">
              <svg className="w-10 h-10 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
            </div>
          </div>
          <h1 className="text-5xl sm:text-6xl font-bold mb-3 bg-gradient-to-r from-cyan-400 via-purple-400 to-pink-400 bg-clip-text text-transparent">
            Kryptonite
          </h1>
          <p className="text-lg sm:text-xl text-slate-400 max-w-2xl mx-auto">
            Advanced mobile static analysis security tool
          </p>
          <div className="flex items-center justify-center gap-6 mt-6 text-sm text-slate-500">
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 rounded-full bg-cyan-500 animate-pulse"></div>
              <span>APK Support</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 rounded-full bg-purple-500 animate-pulse"></div>
              <span>IPA Support</span>
            </div>
          </div>
        </div>

        {/* Upload Section */}
        <div className="glass rounded-2xl shadow-2xl p-8 mb-8 animate-fade-in glass-hover">
          <form onSubmit={handleSubmit} className="space-y-6">
            <div
              onDragOver={handleDragOver}
              onDragLeave={handleDragLeave}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current?.click()}
              className={`relative border-2 border-dashed rounded-xl p-12 text-center cursor-pointer transition-all duration-300 ${
                isDragging
                  ? "border-cyan-500 bg-cyan-500/10 scale-105"
                  : file 
                  ? "border-purple-500/50 bg-purple-500/5"
                  : "border-slate-700 hover:border-cyan-500/50 hover:bg-slate-800/50"
              }`}
            >
              <input
                ref={fileInputRef}
                type="file"
                id="file"
                accept=".apk,.ipa"
                onChange={handleFileChange}
                className="hidden"
              />
              
              <div className="flex flex-col items-center gap-4">
                {file ? (
                  <>
                    <div className="w-20 h-20 bg-gradient-to-br from-purple-500 to-pink-600 rounded-2xl flex items-center justify-center shadow-lg shadow-purple-500/20">
                      <svg className="w-12 h-12 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                      </svg>
                    </div>
                    <div>
                      <p className="text-xl font-semibold text-slate-200 mb-1">{file.name}</p>
                      <p className="text-sm text-slate-400">{(file.size / 1024 / 1024).toFixed(2)} MB</p>
                    </div>
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        setFile(null);
                      }}
                      className="text-sm text-cyan-400 hover:text-cyan-300 transition-colors"
                    >
                      Change file
                    </button>
                  </>
                ) : (
                  <>
                    <div className="w-20 h-20 bg-gradient-to-br from-slate-800 to-slate-700 rounded-2xl flex items-center justify-center">
                      <svg className="w-12 h-12 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
                      </svg>
                    </div>
                    <div>
                      <p className="text-xl font-semibold text-slate-200 mb-2">
                        Drop your file here or click to browse
                      </p>
                      <p className="text-sm text-slate-400">
                        Supports APK and IPA files
                      </p>
                    </div>
                  </>
                )}
              </div>
            </div>

            <button
              type="submit"
              disabled={!file || loading}
              className="w-full bg-gradient-to-r from-cyan-500 to-purple-600 hover:from-cyan-600 hover:to-purple-700 text-white font-semibold py-4 px-6 rounded-xl transition-all duration-300 disabled:opacity-50 disabled:cursor-not-allowed shadow-lg hover:shadow-cyan-500/25 hover:scale-[1.02] active:scale-[0.98] disabled:hover:scale-100"
            >
              {loading ? (
                <div className="flex items-center justify-center gap-3">
                  <svg className="animate-spin h-5 w-5" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none"></circle>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                  <span>Analyzing Security...</span>
                </div>
              ) : (
                <span>Analyze File</span>
              )}
            </button>
          </form>
        </div>

        {/* Error Message */}
        {error && (
          <div className="glass border-red-500/30 rounded-xl p-4 mb-8 animate-fade-in">
            <div className="flex items-center gap-3">
              <svg className="w-6 h-6 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              <p className="text-red-300 font-medium">{error}</p>
            </div>
          </div>
        )}

        {/* Report */}
        {report && (
          <div className="space-y-8 animate-fade-in">
            {/* App Info */}
            <div className="glass rounded-2xl shadow-2xl p-8 glass-hover">
              <h2 className="text-2xl font-bold mb-6 flex items-center gap-3">
                <span className="bg-gradient-to-r from-cyan-400 to-purple-400 bg-clip-text text-transparent">
                  App Information
                </span>
              </h2>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
                {[
                  { label: "Name", value: report.app_info.name, icon: "📱" },
                  { label: "Bundle ID", value: report.app_info.bundle_id, icon: "🆔" },
                  { label: "Version", value: report.app_info.version, icon: "📊" },
                  { label: "Platform", value: report.app_info.platform, icon: "🔧" }
                ].map((item, idx) => (
                  <div key={idx} className="bg-slate-800/30 rounded-xl p-4 border border-slate-700/50 hover:border-cyan-500/30 transition-all">
                    <div className="flex items-center gap-2 mb-2">
                      <span className="text-2xl">{item.icon}</span>
                      <p className="text-sm text-slate-400">{item.label}</p>
                    </div>
                    <p className="font-semibold text-slate-200 truncate">{item.value}</p>
                  </div>
                ))}
              </div>
            </div>

            {/* Summary */}
            <div className="glass rounded-2xl shadow-2xl p-8 glass-hover">
              <h2 className="text-2xl font-bold mb-6 bg-gradient-to-r from-cyan-400 to-purple-400 bg-clip-text text-transparent">
                Security Analysis Summary
              </h2>
              
              <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4 mb-8">
                {[
                  { label: "Critical", count: report.summary.severity_breakdown.Critical || 0, gradient: "from-red-500 to-pink-600" },
                  { label: "High", count: report.summary.severity_breakdown.High || 0, gradient: "from-orange-500 to-red-500" },
                  { label: "Medium", count: report.summary.severity_breakdown.Medium || 0, gradient: "from-yellow-500 to-orange-500" },
                  { label: "Low", count: report.summary.severity_breakdown.Low || 0, gradient: "from-blue-500 to-cyan-500" },
                  { label: "Info", count: report.summary.severity_breakdown.Info || 0, gradient: "from-gray-500 to-slate-500" },
                  { label: "Total", count: report.summary.total_findings, gradient: "from-cyan-500 to-purple-600" }
                ].map((item, idx) => (
                  <div key={idx} className="bg-slate-800/30 rounded-xl p-4 border border-slate-700/50 hover:border-cyan-500/30 transition-all text-center">
                    <div className={`text-3xl font-bold mb-2 bg-gradient-to-r ${item.gradient} bg-clip-text text-transparent`}>
                      {item.count}
                    </div>
                    <p className="text-sm text-slate-400">{item.label}</p>
                  </div>
                ))}
              </div>

              <div className="bg-slate-800/30 rounded-xl p-6 border border-slate-700/50">
                <div className="flex flex-col sm:flex-row items-center justify-between gap-4">
                  <div className="text-center sm:text-left">
                    <p className="text-slate-400 text-sm mb-1">Risk Assessment</p>
                    <p className="text-2xl font-bold text-slate-200">
                      {report.summary.risk_label}
                    </p>
                  </div>
                  <div className="flex items-center gap-4">
                    <div className="relative w-32 h-32">
                      <svg className="transform -rotate-90 w-32 h-32">
                        <circle
                          cx="64"
                          cy="64"
                          r="56"
                          stroke="rgba(148, 163, 184, 0.1)"
                          strokeWidth="8"
                          fill="none"
                        />
                        <circle
                          cx="64"
                          cy="64"
                          r="56"
                          stroke="url(#gradient)"
                          strokeWidth="8"
                          fill="none"
                          strokeDasharray={`${(report.summary.risk_score / 100) * 352} 352`}
                          strokeLinecap="round"
                        />
                        <defs>
                          <linearGradient id="gradient" x1="0%" y1="0%" x2="100%" y2="100%">
                            <stop offset="0%" stopColor="#00d4ff" />
                            <stop offset="100%" stopColor="#a855f7" />
                          </linearGradient>
                        </defs>
                      </svg>
                      <div className="absolute inset-0 flex items-center justify-center">
                        <span className="text-2xl font-bold bg-gradient-to-r from-cyan-400 to-purple-400 bg-clip-text text-transparent">
                          {report.summary.risk_score}
                        </span>
                      </div>
                    </div>
                    <div>
                      <p className="text-sm text-slate-400">Risk Score</p>
                      <p className="text-lg font-semibold text-slate-300">out of 100</p>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* Findings */}
            <div className="glass rounded-2xl shadow-2xl p-8 glass-hover">
              <h2 className="text-2xl font-bold mb-6 bg-gradient-to-r from-cyan-400 to-purple-400 bg-clip-text text-transparent">
                Security Findings
              </h2>
              {report.findings.length === 0 ? (
                <div className="text-center py-12">
                  <div className="w-20 h-20 bg-gradient-to-br from-green-500 to-emerald-600 rounded-2xl flex items-center justify-center mx-auto mb-4 shadow-lg shadow-green-500/20">
                    <svg className="w-12 h-12 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                    </svg>
                  </div>
                  <p className="text-xl text-slate-300 font-semibold mb-2">No Security Issues Found</p>
                  <p className="text-slate-400">Your app looks secure!</p>
                </div>
              ) : (
                <div className="space-y-4">
                  {report.findings.map((finding, index) => (
                    <div
                      key={index}
                      className="bg-slate-800/30 border border-slate-700/50 rounded-xl p-6 hover:border-cyan-500/30 transition-all"
                    >
                      <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-4 mb-4">
                        <h3 className="text-lg font-semibold text-slate-200 flex-1">
                          {finding.title}
                        </h3>
                        <span
                          className={`px-4 py-1.5 rounded-full text-xs font-semibold border ${getSeverityBadgeColor(finding.severity)} whitespace-nowrap`}
                        >
                          {finding.severity.toUpperCase()}
                        </span>
                      </div>
                      
                      <p className="text-slate-300 mb-4 leading-relaxed">
                        {finding.description}
                      </p>
                      
                      <div className="flex flex-wrap gap-2 mb-4">
                        <div className="inline-flex items-center gap-2 px-3 py-1 bg-slate-700/50 rounded-lg text-sm">
                          <svg className="w-4 h-4 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 7h.01M7 3h5c.512 0 1.024.195 1.414.586l7 7a2 2 0 010 2.828l-7 7a2 2 0 01-2.828 0l-7-7A1.994 1.994 0 013 12V7a4 4 0 014-4z" />
                          </svg>
                          <span className="text-slate-300">{finding.owasp_category}</span>
                        </div>
                      </div>

                      {finding.remediation && (
                        <div className="bg-slate-900/50 border border-slate-700/50 rounded-lg p-4 mb-4">
                          <div className="flex items-start gap-2">
                            <svg className="w-5 h-5 text-green-400 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                            </svg>
                            <div className="flex-1">
                              <p className="text-sm font-semibold text-green-400 mb-1">Remediation</p>
                              <p className="text-sm text-slate-300 leading-relaxed">{finding.remediation}</p>
                            </div>
                          </div>
                        </div>
                      )}

                      {finding.evidence.length > 0 && (
                        <div className="space-y-3">
                          <p className="text-sm font-semibold text-slate-300 flex items-center gap-2">
                            <svg className="w-4 h-4 text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                            </svg>
                            Evidence
                          </p>
                          {finding.evidence.map((ev, evIndex) => (
                            <div key={evIndex} className="bg-slate-900/50 border border-slate-700/50 rounded-lg p-4">
                              <div className="flex flex-col sm:flex-row sm:items-center gap-2 mb-2 text-sm">
                                <span className="text-slate-400">📄 {ev.file}</span>
                                {ev.line && (
                                  <span className="text-cyan-400">Line {ev.line}</span>
                                )}
                              </div>
                              {ev.snippet && (
                                <pre className="bg-slate-950 border border-slate-800 rounded-lg p-3 text-xs overflow-x-auto">
                                  <code className="text-slate-300 font-mono">{ev.snippet}</code>
                                </pre>
                              )}
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default App;
