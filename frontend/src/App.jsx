import React, { useState, useEffect, useRef } from 'react';
import {
  Lock, FileCode, AlertTriangle, CheckCircle,
  Loader2, Clock, ArrowRight,
  Key, Package, Settings2, Github, Zap,
} from 'lucide-react';

const SEV = {
  critical: { badge: 'bg-red-500/10 text-red-400 border-red-500/25',    dot: 'bg-red-500',    label: 'CRITICAL' },
  high:     { badge: 'bg-orange-500/10 text-orange-400 border-orange-500/25', dot: 'bg-orange-500', label: 'HIGH' },
  medium:   { badge: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/25', dot: 'bg-yellow-500', label: 'MEDIUM' },
  low:      { badge: 'bg-slate-800 text-slate-400 border-slate-700',     dot: 'bg-slate-500',  label: 'LOW' },
};

const Logo = () => (
  <div className="w-8 h-8 bg-violet-600 rounded-lg flex items-center justify-center shadow-lg shadow-violet-900/40">
    <Lock className="w-4 h-4 text-white" />
  </div>
);

const SeverityBadge = ({ severity }) => {
  const c = SEV[severity] ?? SEV.low;
  return (
    <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-bold border shrink-0 ${c.badge}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${c.dot}`} />
      {c.label}
    </span>
  );
};

const TypeIcon = ({ type }) => {
  if (type === 'secret') return <Key className="w-3.5 h-3.5 text-red-400 shrink-0 mt-0.5" />;
  if (type === 'cve')    return <Package className="w-3.5 h-3.5 text-orange-400 shrink-0 mt-0.5" />;
  return <Settings2 className="w-3.5 h-3.5 text-yellow-400 shrink-0 mt-0.5" />;
};

const StatusIcon = ({ status }) => {
  if (status === 'scanning') return <Loader2 className="w-3.5 h-3.5 text-violet-400 animate-spin shrink-0" />;
  if (status === 'done')     return <CheckCircle className="w-3.5 h-3.5 text-emerald-400 shrink-0" />;
  if (status === 'error')    return <AlertTriangle className="w-3.5 h-3.5 text-red-400 shrink-0" />;
  return <Clock className="w-3.5 h-3.5 text-slate-700 shrink-0" />;
};

const ScoreRing = ({ score, size = 96, stroke = 8 }) => {
  const r = (size - stroke) / 2;
  const c = r * 2 * Math.PI;
  const offset = c - (score / 100) * c;
  const color = score >= 80 ? '#10B981' : score >= 50 ? '#F59E0B' : '#EF4444';
  const label = score >= 80 ? 'Secure' : score >= 50 ? 'At Risk' : 'Critical';
  return (
    <div className="flex flex-col items-center gap-1">
      <div className="relative" style={{ width: size, height: size }}>
        <svg className="-rotate-90 absolute inset-0" width={size} height={size}>
          <circle cx={size/2} cy={size/2} r={r} strokeWidth={stroke} stroke="#1E293B" fill="none" />
          <circle cx={size/2} cy={size/2} r={r} strokeWidth={stroke}
            stroke={color} fill="none" strokeLinecap="round"
            strokeDasharray={c} strokeDashoffset={offset}
            style={{ transition: 'stroke-dashoffset 1.2s cubic-bezier(.4,0,.2,1)' }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-2xl font-extrabold text-white leading-none">{score}</span>
          <span className="text-[10px] text-slate-600 font-medium">/100</span>
        </div>
      </div>
      <span className="text-xs font-semibold" style={{ color }}>{label}</span>
    </div>
  );
};

const ScorePill = ({ score }) => {
  const color = score >= 80
    ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/25'
    : score >= 50
      ? 'bg-yellow-500/10 text-yellow-400 border-yellow-500/25'
      : 'bg-red-500/10 text-red-400 border-red-500/25';
  return (
    <span className={`px-2.5 py-1 rounded-lg text-sm font-bold border ${color} shrink-0`}>
      {score}
    </span>
  );
};

export default function App() {
  const [view, setView]             = useState('home');
  const [input, setInput]           = useState('');
  const [scanUsername, setScanUsername] = useState('');
  const [reportData, setReportData] = useState(null);
  const [jobId, setJobId]           = useState(null);
  const [progress, setProgress]     = useState(null);
  const [error, setError]           = useState(null);
  const logsEndRef = useRef(null);
  const inputRef   = useRef(null);

  const extractUsername = (raw) => {
    const t = raw.trim().replace(/\/$/, '');
    const m = t.match(/^(?:https?:\/\/)?github\.com\/([A-Za-z0-9_.-]+)/i);
    return m ? m[1] : t;
  };

  const startScan = async (rawInput) => {
    const username = extractUsername(rawInput);
    if (!username) return;
    setError(null);
    setProgress(null);
    setScanUsername(username);
    setView('scanning');
    try {
      const res  = await fetch(`/api/scan/${username}`, { method: 'POST' });
      const data = await res.json();
      if (data.jobId) {
        setJobId(data.jobId);
      } else {
        throw new Error(data.message || 'Failed to start scan');
      }
    } catch (err) {
      setError(err.message);
      setView('home');
    }
  };

  const reset = () => {
    setView('home');
    setReportData(null);
    setJobId(null);
    setProgress(null);
    setInput('');
    setTimeout(() => inputRef.current?.focus(), 80);
  };

  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [progress?.logs]);

  useEffect(() => {
    if (view !== 'scanning' || !jobId) return;
    const iv = setInterval(async () => {
      try {
        const res  = await fetch(`/api/scan/result/${jobId}`);
        const data = await res.json();
        if (data.status === 'completed') {
          setReportData(data.report);
          setView('report');
          clearInterval(iv);
        } else if (data.progress) {
          setProgress(data.progress);
        }
      } catch { /* retry */ }
    }, 800);
    return () => clearInterval(iv);
  }, [view, jobId]);

  const pct = progress
    ? Math.round((progress.scannedRepos / Math.max(progress.totalRepos, 1)) * 100)
    : 0;

  const countBySeverity = (repos) => {
    const c = { critical: 0, high: 0, medium: 0, low: 0 };
    repos?.forEach(r => r.findings?.forEach(f => { if (f.severity in c) c[f.severity]++; }));
    return c;
  };

  const Header = ({ showReset }) => (
    <header className="border-b border-slate-800/70 px-5 sm:px-8 py-4 flex items-center justify-between shrink-0">
      <button onClick={reset} className="flex items-center gap-2.5 group">
        <Logo />
        <span className="font-bold text-white tracking-tight text-[15px] group-hover:text-violet-300 transition-colors">
          VaultScan
        </span>
      </button>
      <div className="flex items-center gap-4">
        {showReset && (
          <button
            onClick={reset}
            className="text-sm text-slate-400 hover:text-white px-3 py-1.5 rounded-lg hover:bg-slate-800 transition-all"
          >
            ← New scan
          </button>
        )}
        <a
          href="https://github.com"
          target="_blank"
          rel="noopener noreferrer"
          className="text-slate-500 hover:text-slate-300 transition-colors"
          title="View source"
        >
          <Github className="w-5 h-5" />
        </a>
      </div>
    </header>
  );

  if (view === 'home') return (
    <div className="min-h-screen bg-[#060912] text-slate-200 flex flex-col">
      <Header />

      {error && (
        <div className="mx-auto mt-4 px-4 py-3 bg-red-950/60 border border-red-500/30 rounded-xl text-red-300 text-sm max-w-md w-full">
          {error}
        </div>
      )}

      <main className="flex-1 flex flex-col items-center justify-center px-6 pb-20 animate-fade-up">
        <div className="inline-flex items-center gap-2 px-3.5 py-1.5 bg-violet-500/10 border border-violet-500/20 rounded-full text-violet-300 text-xs font-semibold mb-8 tracking-wide">
          <Zap className="w-3 h-3" />
          Open-source · Free · No signup
        </div>

        <h1 className="text-5xl sm:text-[64px] font-black tracking-tight text-center mb-5 leading-[1.06] max-w-3xl">
          <span className="text-white">Security audit for</span>
          <br />
          <span className="bg-gradient-to-r from-violet-400 via-fuchsia-400 to-pink-300 bg-clip-text text-transparent">
            every repository.
          </span>
        </h1>

        <p className="text-slate-400 text-lg text-center max-w-xl mb-10 leading-relaxed">
          Paste any GitHub profile URL to scan all public repositories for
          leaked secrets, known CVEs, and security misconfigurations — in seconds.
        </p>

        <div className="w-full max-w-md">
          <div className="flex gap-2">
            <div className="flex-1 flex items-center gap-2.5 bg-slate-900 border border-slate-700/80 rounded-xl px-4 focus-within:border-violet-500 focus-within:ring-2 focus-within:ring-violet-500/15 transition-all">
              <Github className="w-4 h-4 text-slate-600 shrink-0" />
              <input
                ref={inputRef}
                type="text"
                placeholder="github.com/username"
                className="flex-1 bg-transparent py-3.5 text-sm outline-none placeholder-slate-600 text-slate-100"
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && startScan(input)}
                autoFocus
              />
            </div>
            <button
              onClick={() => startScan(input)}
              disabled={!input.trim()}
              className="px-5 py-3.5 bg-violet-600 hover:bg-violet-500 active:bg-violet-700 disabled:opacity-25 disabled:cursor-not-allowed rounded-xl font-semibold text-sm flex items-center gap-2 shrink-0 shadow-lg shadow-violet-900/30"
            >
              Scan
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>

          <p className="text-xs text-slate-700 text-center mt-3">
            Try: <button onClick={() => setInput('https://github.com/torvalds')} className="text-slate-500 hover:text-violet-400 transition-colors underline underline-offset-2">torvalds</button>
            {' · '}
            <button onClick={() => setInput('https://github.com/sindresorhus')} className="text-slate-500 hover:text-violet-400 transition-colors underline underline-offset-2">sindresorhus</button>
          </p>
        </div>

        <div className="flex flex-wrap justify-center gap-8 mt-14 text-sm">
          {[
            { icon: <Key className="w-4 h-4 text-red-400" />,      label: '40+ secret patterns',        sub: 'AWS, GitHub, Stripe…' },
            { icon: <Package className="w-4 h-4 text-orange-400" />, label: 'OSV vulnerability database', sub: 'npm, PyPI, Go, Rust…' },
            { icon: <Settings2 className="w-4 h-4 text-yellow-400" />, label: 'Misconfiguration scanner', sub: 'Docker, CI, configs…' },
          ].map(({ icon, label, sub }) => (
            <div key={label} className="flex flex-col items-center gap-1.5 text-center">
              <div className="w-10 h-10 rounded-xl bg-slate-900 border border-slate-800 flex items-center justify-center mb-1">
                {icon}
              </div>
              <span className="text-slate-300 font-medium">{label}</span>
              <span className="text-slate-600 text-xs">{sub}</span>
            </div>
          ))}
        </div>
      </main>
    </div>
  );

  if (view === 'scanning') return (
    <div className="min-h-screen bg-[#060912] text-slate-200 flex flex-col">
      <Header />

      <main className="flex-1 flex flex-col items-center px-5 sm:px-8 py-10">
        <div className="w-full max-w-3xl animate-fade-up">

          <div className="flex items-end justify-between mb-2">
            <div>
              <h2 className="text-xl font-bold text-white">
                Scanning <span className="text-violet-400">@{scanUsername}</span>
              </h2>
              <p className="text-slate-500 text-sm mt-0.5">
                {progress
                  ? `${progress.scannedRepos} of ${progress.totalRepos} repositories complete`
                  : 'Fetching repository list…'}
              </p>
            </div>
            {progress && (
              <span className="text-4xl font-black text-violet-400 tabular-nums leading-none pb-0.5">
                {pct}%
              </span>
            )}
          </div>

          <div className="h-1 bg-slate-800 rounded-full overflow-hidden mb-8">
            <div
              className="h-full bg-gradient-to-r from-violet-600 to-fuchsia-500 rounded-full transition-all duration-500 ease-out"
              style={{ width: `${pct || 2}%` }}
            />
          </div>

          {progress?.repos ? (
            <div className="space-y-1.5 mb-6 max-h-80 overflow-y-auto pr-1">
              {progress.repos.map((repo, i) => (
                <div
                  key={repo.id}
                  className={`flex items-center gap-3 px-4 py-2.5 rounded-xl border text-sm transition-all ${
                    repo.status === 'scanning' ? 'bg-violet-500/5 border-violet-500/20' :
                    repo.status === 'done'     ? 'bg-emerald-500/5 border-emerald-500/15' :
                    repo.status === 'error'    ? 'bg-red-500/5 border-red-500/15' :
                                                 'bg-slate-900/30 border-slate-800/50'
                  }`}
                >
                  <span className="text-slate-700 text-xs w-5 text-right shrink-0 tabular-nums font-mono">{i + 1}</span>
                  <StatusIcon status={repo.status} />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="font-medium truncate">{repo.name}</span>
                      {repo.language && (
                        <span className="text-[10px] text-slate-600 bg-slate-800/80 px-1.5 py-0.5 rounded shrink-0">
                          {repo.language}
                        </span>
                      )}
                    </div>
                    {repo.status === 'scanning' && repo.currentFile && (
                      <p className="text-xs text-violet-400/50 font-mono truncate mt-0.5">{repo.currentFile}</p>
                    )}
                    {repo.status === 'done' && (
                      <p className="text-xs mt-0.5">
                        {repo.findingsCount > 0
                          ? <span className="text-yellow-500/90">{repo.findingsCount} issue{repo.findingsCount !== 1 ? 's' : ''}</span>
                          : <span className="text-emerald-500/80">clean</span>}
                      </p>
                    )}
                  </div>
                  {repo.status === 'pending' && (
                    <span className="text-[11px] text-slate-700 shrink-0">queued</span>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <div className="flex items-center gap-2.5 text-slate-500 mb-6 py-2">
              <Loader2 className="w-4 h-4 animate-spin text-violet-500" />
              <span className="text-sm">Connecting to scan engine…</span>
            </div>
          )}

          {progress?.logs?.length > 0 && (
            <div className="bg-slate-950 border border-slate-800 rounded-xl overflow-hidden">
              <div className="flex items-center gap-1.5 px-4 py-2.5 border-b border-slate-800/80">
                <span className="w-2.5 h-2.5 rounded-full bg-red-500/50" />
                <span className="w-2.5 h-2.5 rounded-full bg-yellow-500/50" />
                <span className="w-2.5 h-2.5 rounded-full bg-green-500/50" />
                <span className="ml-2 text-[11px] text-slate-600 font-medium uppercase tracking-wider">Live output</span>
              </div>
              <div className="p-4 max-h-36 overflow-y-auto space-y-0.5">
                {progress.logs.slice(-40).map((log, i) => (
                  <div key={i} className="text-xs text-slate-500 font-mono leading-5">
                    <span className="text-violet-700 select-none">›</span> {log}
                  </div>
                ))}
                <div ref={logsEndRef} />
              </div>
            </div>
          )}
        </div>
      </main>
    </div>
  );

  if (view === 'report' && reportData) {
    const counts      = countBySeverity(reportData.repos);
    const totalIssues = Object.values(counts).reduce((s, n) => s + n, 0);
    const sortedRepos = [...reportData.repos].sort((a, b) => a.score - b.score);

    return (
      <div className="min-h-screen bg-[#060912] text-slate-200 flex flex-col">
        <Header showReset />

        <main className="flex-1 flex flex-col items-center px-4 sm:px-6 py-8 overflow-y-auto">
          <div className="w-full max-w-4xl animate-fade-up space-y-4">

            <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 flex flex-col sm:flex-row items-start sm:items-center gap-6">
              <ScoreRing score={reportData.overallScore} size={96} stroke={8} />

              <div className="flex-1 min-w-0">
                <div className="flex items-baseline gap-3 flex-wrap">
                  <h2 className="text-2xl font-extrabold text-white">@{reportData.username}</h2>
                  <span className="text-slate-500 text-sm">{reportData.scannedRepos} repos scanned</span>
                </div>

                <div className="flex flex-wrap gap-2 mt-3">
                  {totalIssues === 0 ? (
                    <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/25">
                      <CheckCircle className="w-3 h-3" /> No issues detected
                    </span>
                  ) : (
                    Object.entries(counts)
                      .filter(([, n]) => n > 0)
                      .map(([sev, n]) => {
                        const c = SEV[sev];
                        return (
                          <span key={sev} className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-bold border ${c.badge}`}>
                            <span className={`w-1.5 h-1.5 rounded-full ${c.dot}`} />
                            {n} {c.label}
                          </span>
                        );
                      })
                  )}
                </div>
              </div>
            </div>

            {sortedRepos.map(repo => (
              <div
                key={repo.id}
                className="bg-slate-900/50 border border-slate-800 rounded-xl overflow-hidden hover:border-slate-700/80 transition-colors"
              >
                <div className="flex items-center justify-between px-5 py-3.5 gap-3">
                  <div className="flex items-center gap-2.5 min-w-0">
                    <FileCode className="w-4 h-4 text-slate-600 shrink-0" />
                    <span className="font-semibold text-slate-100 truncate">{repo.name}</span>
                    {repo.language && (
                      <span className="text-[10px] text-slate-600 bg-slate-800/80 px-1.5 py-0.5 rounded shrink-0">
                        {repo.language}
                      </span>
                    )}
                  </div>
                  <ScorePill score={repo.score} />
                </div>

                {repo.findings.length > 0 ? (
                  <div className="border-t border-slate-800/70 divide-y divide-slate-800/50">
                    {repo.findings.map((f, idx) => (
                      <div key={idx} className="flex items-start gap-3 px-5 py-3">
                        <TypeIcon type={f.type} />
                        <div className="flex-1 min-w-0">
                          <p className="text-sm text-slate-200 leading-snug">{f.message}</p>
                          {f.file && f.file !== 'N/A' && (
                            <p className="text-xs text-slate-600 font-mono mt-1 truncate">{f.file}</p>
                          )}
                        </div>
                        <SeverityBadge severity={f.severity} />
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="border-t border-slate-800/70 px-5 py-3 flex items-center gap-2 text-sm text-emerald-500/70">
                    <CheckCircle className="w-3.5 h-3.5" />
                    No vulnerabilities detected
                  </div>
                )}
              </div>
            ))}

            <p className="text-center text-xs text-slate-700 pb-4">
              Powered by{' '}
              <a href="https://osv.dev" target="_blank" rel="noopener noreferrer" className="text-slate-600 hover:text-slate-400 transition-colors">OSV Database</a>
              {' · '}
              <a href="https://docs.github.com/en/rest" target="_blank" rel="noopener noreferrer" className="text-slate-600 hover:text-slate-400 transition-colors">GitHub API</a>
            </p>
          </div>
        </main>
      </div>
    );
  }

  return null;
}
