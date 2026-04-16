import React, { useState, useEffect } from 'react';
import { 
  Search, Shield, ShieldAlert, ShieldCheck, Github, 
  ChevronDown, ChevronUp, FileCode, Clock, AlertTriangle, 
  CheckCircle, Loader2, Lock, FileWarning
} from 'lucide-react';

// --- MOCK DATA ---
const generateMockReport = (username) => ({
  username,
  overallScore: 72,
  scannedRepos: 12,
  repos: [
    {
      id: 1,
      name: 'ecommerce-api-node',
      language: 'TypeScript',
      score: 45,
      findings: [
        { id: 'f1', type: 'secret', severity: 'critical', message: 'AWS_ACCESS_KEY_ID encontrada hardcoded', file: 'src/config/aws.ts', line: 14, commit: 'a3f2c1d', timeAgo: 'há 8 meses' },
        { id: 'f2', type: 'cve', severity: 'high', message: 'Vulnerabilidade no pacote "jsonwebtoken" (CVE-2022-23529)', file: 'package.json', line: 42, commit: null, timeAgo: null }
      ]
    },
    {
      id: 2,
      name: 'react-dashboard-admin',
      language: 'JavaScript',
      score: 85,
      findings: [
        { id: 'f3', type: 'cve', severity: 'medium', message: 'ReDoS em expressão regular do "validator" (CVE-2021-3765)', file: 'package-lock.json', line: 1205, commit: null, timeAgo: null }
      ]
    },
    {
      id: 3,
      name: 'landing-page-institucional',
      language: 'HTML/CSS',
      score: 100,
      findings: []
    }
  ]
});

// --- COMPONENTES ---
const ScoreRing = ({ score, size = 120, strokeWidth = 8 }) => {
  const radius = (size - strokeWidth) / 2;
  const circumference = radius * 2 * Math.PI;
  const offset = circumference - (score / 100) * circumference;
  let colorClass = 'text-red-500';
  if (score >= 80) colorClass = 'text-emerald-500';
  else if (score >= 50) colorClass = 'text-amber-500';

  return (
    <div className="relative flex items-center justify-center" style={{ width: size, height: size }}>
      <svg className="transform -rotate-90 absolute" width={size} height={size}>
        <circle cx={size / 2} cy={size / 2} r={radius} className="text-slate-700" strokeWidth={strokeWidth} stroke="currentColor" fill="transparent" />
        <circle cx={size / 2} cy={size / 2} r={radius} className={`${colorClass} transition-all duration-1000 ease-out`} strokeWidth={strokeWidth} strokeDasharray={circumference} strokeDashoffset={offset} strokeLinecap="round" stroke="currentColor" fill="transparent" />
      </svg>
      <div className="absolute flex flex-col items-center justify-center">
        <span className="text-3xl font-bold text-slate-100">{score}</span>
        <span className="text-xs text-slate-400">/ 100</span>
      </div>
    </div>
  );
};

export default function App() {
  const [view, setView] = useState('home');
  const [scanUsername, setScanUsername] = useState('');
  const [reportData, setReportData] = useState(null);
  const [jobId, setJobId] = useState(null);
  const [error, setError] = useState(null);

  const API_BASE = 'http://localhost:3000/api'; // Ajuste conforme necessário

  const handleStartScan = async (username) => {
    setError(null);
    setScanUsername(username);
    setView('scanning');

    try {
        const response = await fetch(`${API_BASE}/scan/${username}`, { method: 'POST' });
        const data = await response.json();
        if (data.jobId) {
            setJobId(data.jobId);
        } else {
            throw new Error(data.message || 'Falha ao iniciar scan');
        }
    } catch (err) {
        setError(err.message);
        setView('home');
    }
  };

  useEffect(() => {
    let interval;
    if (view === 'scanning' && jobId) {
        interval = setInterval(async () => {
            try {
                const response = await fetch(`${API_BASE}/scan/result/${jobId}`);
                const data = await response.json();
                
                if (data.status === 'completed') {
                    setReportData(data.report);
                    setView('report');
                    clearInterval(interval);
                }
            } catch (err) {
                console.error("Erro no polling:", err);
            }
        }, 3000);
    }
    return () => clearInterval(interval);
  }, [view, jobId]);

  return (
    <div className="min-h-screen bg-slate-950 text-slate-200 flex flex-col items-center justify-center p-8">
      {error && <div className="mb-4 p-4 bg-red-900/50 border border-red-500 rounded text-red-200">{error}</div>}
      
      {view === 'home' && (
        <div className="text-center">
           <Shield className="w-16 h-16 text-indigo-500 mx-auto mb-4" />
           <h1 className="text-4xl font-bold mb-8">Reposcope</h1>
           <div className="flex gap-2">
             <input 
               type="text" 
               placeholder="GitHub Username" 
               className="px-4 py-2 bg-slate-900 border border-slate-700 rounded-lg outline-none focus:border-indigo-500"
               value={scanUsername}
               onChange={(e) => setScanUsername(e.target.value)}
             />
             <button 
               onClick={() => handleStartScan(scanUsername || 'octocat')} 
               className="px-6 py-2 bg-indigo-600 hover:bg-indigo-700 rounded-lg font-bold transition-colors"
             >
               Escanear
             </button>
           </div>
        </div>
      )}

      {view === 'scanning' && (
        <div className="flex flex-col items-center">
            <Loader2 className="w-10 h-10 animate-spin text-indigo-500 mb-4" /> 
            <div className="text-xl">A analisar repositórios de <strong>@{scanUsername}</strong>...</div>
            <div className="text-sm text-slate-400 mt-2">Isto pode demorar alguns minutos.</div>
        </div>
      )}

      {view === 'report' && reportData && (
         <div className="w-full max-w-4xl bg-slate-900 p-8 rounded-xl border border-slate-800 shadow-2xl overflow-y-auto max-h-[85vh]">
            <div className="flex justify-between items-start mb-8 border-b border-slate-700 pb-6">
                <div>
                    <h2 className="text-3xl font-bold">Relatório: @{reportData.username}</h2>
                    <p className="text-slate-400 mt-1">{reportData.scannedRepos} repositórios analisados</p>
                </div>
                <ScoreRing score={reportData.overallScore} size={110} strokeWidth={8} />
            </div>

            <div className="grid gap-4">
                {reportData.repos.map(repo => (
                    <div key={repo.id} className="p-4 bg-slate-950/50 rounded-lg border border-slate-800 hover:border-slate-700 transition-colors">
                        <div className="flex justify-between items-center mb-3">
                            <div className="flex items-center gap-2">
                                <FileCode className="w-5 h-5 text-indigo-400" />
                                <span className="font-bold text-lg">{repo.name}</span>
                                <span className="text-xs bg-slate-800 px-2 py-0.5 rounded text-slate-400">{repo.language || 'N/A'}</span>
                            </div>
                            <span className={`px-3 py-1 rounded-full text-sm font-bold ${repo.score >= 80 ? 'bg-emerald-500/10 text-emerald-500' : 'bg-amber-500/10 text-amber-500'}`}>
                                Score: {repo.score}
                            </span>
                        </div>
                        
                        {repo.findings.length > 0 ? (
                            <div className="grid gap-2 mt-2">
                                {repo.findings.map((f, idx) => (
                                    <div key={idx} className="flex items-start gap-3 p-2 bg-red-500/5 border border-red-500/10 rounded">
                                        <AlertTriangle className="w-4 h-4 text-red-500 mt-0.5 flex-shrink-0" />
                                        <div className="text-sm">
                                            <span className="font-bold text-red-400 mr-2">[{f.severity.toUpperCase()}]</span>
                                            <span className="text-slate-200">{f.message}</span>
                                            <div className="text-xs text-slate-500 mt-1">Local: {f.file}</div>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        ) : (
                            <div className="flex items-center gap-2 text-sm text-emerald-500/80">
                                <CheckCircle className="w-4 h-4" /> Nenhum problema encontrado
                            </div>
                        )}
                    </div>
                ))}
            </div>

            <button 
                onClick={() => setView('home')} 
                className="mt-8 px-6 py-2 border border-slate-700 hover:bg-slate-800 rounded-lg transition-colors inline-flex items-center gap-2"
            >
                ← Nova Busca
            </button>
         </div>
      )}
    </div>
  );
}
