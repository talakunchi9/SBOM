import React, { useState, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  GitFork,
  Search,
  Info,
  Fingerprint,
  ChevronDown,
  Download,
  Package,
  Layers,
  FileCheck2,
  Scale,
  Wrench,
  ArrowRight,
} from 'lucide-react';
import { useAppState } from '../../context/AppStateContext';

export const SupplyChain: React.FC = () => {
  const navigate = useNavigate();
  const {
    components,
    vulnerabilities,
    systemStatus,
    triggerSelfHeal,
    addToast,
  } = useAppState();

  const [activeTab, setActiveTab] = useState<'all' | 'copyleft' | 'transitive' | 'unsigned' | 'malicious' | 'typosquat'>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [riskFilter, setRiskFilter] = useState('all');

  // Derive live supply-chain findings from components and vulnerabilities
  const allFindings = useMemo(() => {
    const list: Array<{
      id: string;
      category: 'Copyleft' | 'Transitive CVE' | 'Unsigned' | 'Malicious / critical' | 'Typosquat';
      package: string;
      version: string;
      ecosystem: string;
      risk: 'Critical' | 'High' | 'Medium' | 'Low' | 'Safe';
      details: string;
      project: string;
    }> = [];

    // 1. Copyleft exposure (GPL, AGPL, SSPL, LGPL, etc.)
    components.forEach((c) => {
      const lic = (c.license || '').toUpperCase();
      if (lic.includes('GPL') || lic.includes('AGPL') || lic.includes('SSPL') || lic.includes('COPYLEFT')) {
        list.push({
          id: `copyleft-${c.id || c.name}-${c.version}`,
          category: 'Copyleft',
          package: c.name,
          version: c.version,
          ecosystem: c.ecosystem || 'npm',
          risk: 'Medium',
          details: `Copyleft license (${c.license}) may require source disclosure if distributed.`,
          project: c.project || 'Global Inventory',
        });
      }
    });

    // 2. Transitive CVEs
    vulnerabilities.forEach((v) => {
      const matchingComp = components.find(c => c.name.toLowerCase() === v.package.toLowerCase());
      const isTransitive = matchingComp ? (matchingComp.dependencies ?? 0) > 0 : false;
      if (isTransitive || v.cve) {
        list.push({
          id: `trans-${v.id || v.cve}-${v.package}`,
          category: 'Transitive CVE',
          package: v.package,
          version: v.version,
          ecosystem: matchingComp?.ecosystem || 'npm',
          risk: (v.severity as any) || 'High',
          details: `${v.cve}: ${v.title || 'Vulnerability in dependency chain'}`,
          project: v.project || 'Global Inventory',
        });
      }
    });

    // 3. Malicious / critical flagged
    vulnerabilities
      .filter((v) => (v.severity || '').toUpperCase() === 'CRITICAL')
      .forEach((v) => {
        list.push({
          id: `malicious-${v.id || v.cve}`,
          category: 'Malicious / critical',
          package: v.package,
          version: v.version,
          ecosystem: 'npm',
          risk: 'Critical',
          details: `Critical advisory flagged: ${v.cve}`,
          project: v.project || 'Global Inventory',
        });
      });

    return list;
  }, [components, vulnerabilities]);

  // Compute metric counts
  const copyleftCount = useMemo(() => allFindings.filter((f) => f.category === 'Copyleft').length, [allFindings]);
  const transitiveCveCount = useMemo(() => allFindings.filter((f) => f.category === 'Transitive CVE').length, [allFindings]);
  const unsignedCount = useMemo(() => allFindings.filter((f) => f.category === 'Unsigned').length, [allFindings]);
  const maliciousCount = useMemo(() => allFindings.filter((f) => f.category === 'Malicious / critical').length, [allFindings]);
  const typosquatCount = useMemo(() => allFindings.filter((f) => f.category === 'Typosquat').length, [allFindings]);

  // Direct vs Transitive deps from components
  const directDepsCount = useMemo(() => {
    return components.filter((c) => (c.dependencies ?? 0) === 0 && components.length > 0).length;
  }, [components]);

  const transitiveDepsCount = useMemo(() => {
    return components.filter((c) => (c.dependencies ?? 0) > 0).length;
  }, [components]);

  const catalogSize = components.length;

  const ecosystemsCount = useMemo(() => {
    const ecos = new Set(components.map((c) => (c.ecosystem || '').toLowerCase()).filter(Boolean));
    return ecos.size;
  }, [components]);

  const integrityCoverage = useMemo(() => {
    if (components.length === 0) return 0;
    const covered = components.filter((c) => Boolean(c.purl)).length;
    return Math.round((covered / components.length) * 100);
  }, [components]);

  // Filtered findings
  const filteredFindings = useMemo(() => {
    return allFindings.filter((f) => {
      if (activeTab === 'copyleft' && f.category !== 'Copyleft') return false;
      if (activeTab === 'transitive' && f.category !== 'Transitive CVE') return false;
      if (activeTab === 'unsigned' && f.category !== 'Unsigned') return false;
      if (activeTab === 'malicious' && f.category !== 'Malicious / critical') return false;
      if (activeTab === 'typosquat' && f.category !== 'Typosquat') return false;

      if (riskFilter !== 'all' && f.risk.toLowerCase() !== riskFilter.toLowerCase()) return false;

      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        return (
          f.package.toLowerCase().includes(q) ||
          f.project.toLowerCase().includes(q) ||
          f.details.toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [allFindings, activeTab, riskFilter, searchQuery]);

  const handleExportCsv = () => {
    const headers = ['Category', 'Package', 'Version', 'Ecosystem', 'Risk', 'Details', 'Project'];
    const rows = filteredFindings.map((f) => [
      f.category,
      f.package,
      f.version,
      f.ecosystem,
      f.risk,
      `"${f.details.replace(/"/g, '""')}"`,
      f.project,
    ]);

    const csvContent = [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', 'supply_chain_findings.csv');
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);

    addToast({
      type: 'success',
      title: 'Export Complete',
      message: 'Supply chain findings exported as CSV.',
    });
  };

  return (
    <div className="space-y-4 animate-fadeIn pb-12 font-sans">
      {/* System Status Indicators Row */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-red-50 dark:bg-[#201015] border border-red-200 dark:border-[#4a1820] text-red-700 dark:text-[#f87171] text-xs font-semibold shadow-2xs">
          <span className="w-1.5 h-1.5 rounded-full bg-[#ef4444]" />
          <span>
            Scan API {systemStatus.scanApi === 'connected' ? 'connected' : 'unavailable'}
          </span>
        </div>
        <div className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-red-50 dark:bg-[#201015] border border-red-200 dark:border-[#4a1820] text-red-700 dark:text-[#f87171] text-xs font-semibold shadow-2xs">
          <span className="w-1.5 h-1.5 rounded-full bg-[#ef4444]" />
          <span>
            Postgres {systemStatus.postgres === 'connected' ? 'connected' : 'unavailable'}
          </span>
        </div>
        <div className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-red-50 dark:bg-[#201015] border border-red-200 dark:border-[#4a1820] text-red-700 dark:text-[#f87171] text-xs font-semibold shadow-2xs">
          <span className="w-1.5 h-1.5 rounded-full bg-[#ef4444]" />
          <span>
            Scans {systemStatus.scans === 'running' ? 'running' : 'unavailable'}
          </span>
        </div>
        <button
          type="button"
          onClick={triggerSelfHeal}
          className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-white dark:bg-[#131b2e] hover:bg-gray-50 dark:hover:bg-[#1e293b] border border-gray-200 dark:border-gray-700/60 text-gray-700 dark:text-gray-300 hover:text-gray-900 dark:hover:text-white text-xs font-semibold transition-colors cursor-pointer shadow-2xs"
        >
          <Wrench className="w-3 h-3 text-gray-500 dark:text-gray-400" />
          <span>Self-heal</span>
        </button>
      </div>

      {/* Page Subtitle & Action Buttons */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pt-1">
        <div className="flex items-start gap-2">
          <Info className="w-4 h-4 text-gray-400 shrink-0 mt-0.5" />
          <p className="text-xs sm:text-sm text-gray-600 dark:text-gray-400 leading-relaxed max-w-3xl">
            Provenance, copyleft exposure, typosquats, unsigned artefacts, and vulnerable transitive paths from live engine inventory.
          </p>
        </div>

        <div className="flex items-center gap-2.5 shrink-0">
          <button
            type="button"
            onClick={() => navigate('/software-inventory')}
            className="px-3.5 py-1.5 rounded-lg bg-white dark:bg-[#131b2e] hover:bg-gray-50 dark:hover:bg-[#1e293b] border border-gray-300 dark:border-gray-700 text-gray-700 dark:text-gray-200 hover:text-gray-900 dark:hover:text-white text-xs font-semibold transition-colors cursor-pointer shadow-2xs"
          >
            Open inventory
          </button>
          <button
            type="button"
            onClick={handleExportCsv}
            className="px-3.5 py-1.5 rounded-lg bg-[#ef4444] hover:bg-[#dc2626] text-white text-xs font-semibold flex items-center gap-1.5 transition-colors cursor-pointer shadow-2xs"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export CSV</span>
          </button>
        </div>
      </div>

      {/* 5 Top Summary Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
        {/* Card 1: DIRECT DEPS (Blue Theme) */}
        <div className="bg-gradient-to-b from-blue-50/40 via-white to-white dark:from-blue-950/20 dark:via-[#111827] dark:to-[#111827] border border-blue-100/90 dark:border-gray-800 hover:border-blue-400 dark:hover:border-blue-500 rounded-xl p-3.5 sm:p-4 shadow-2xs hover:shadow-md hover:shadow-blue-500/5 hover:-translate-y-0.5 transition-all duration-200 min-h-[116px] flex flex-col justify-between group cursor-pointer">
          <div className="flex items-start justify-between gap-1.5">
            <div className="flex items-center gap-2 min-w-0 pr-1">
              <div className="w-7 h-7 rounded-lg bg-blue-100/80 dark:bg-blue-900/40 text-blue-600 dark:text-blue-400 flex items-center justify-center shrink-0 border border-blue-200/50 dark:border-blue-800/50 shadow-2xs">
                <GitFork className="w-3.5 h-3.5" />
              </div>
              <span className="text-[11px] font-bold uppercase tracking-tight text-gray-700 dark:text-gray-300 leading-snug">
                DIRECT DEPS
              </span>
            </div>
            <div className="relative group/info shrink-0 -mr-1 -mt-0.5">
              <button
                type="button"
                className="p-1 rounded-full text-gray-400 hover:text-blue-600 dark:hover:text-blue-400 hover:bg-blue-50 dark:hover:bg-blue-950/40 transition-colors cursor-help"
                aria-label="Direct Dependencies Info"
              >
                <Info className="w-3.5 h-3.5" />
              </button>
              <div className="absolute right-0 bottom-full mb-2 opacity-0 invisible group-hover/info:opacity-100 group-hover/info:visible transition-all duration-150 w-56 p-2.5 bg-gray-900 text-white text-[11px] normal-case font-normal rounded-lg shadow-xl z-50 pointer-events-none leading-relaxed">
                <div className="font-bold text-white mb-0.5">Direct Dependencies</div>
                Primary root dependencies explicitly declared in manifest files.
                <div className="absolute top-full right-2 border-4 border-transparent border-t-gray-900" />
              </div>
            </div>
          </div>

          <div className="mt-3 flex items-end justify-between">
            <div>
              <h2 className="text-2xl font-black text-gray-900 dark:text-white group-hover:text-blue-600 dark:group-hover:text-blue-400 transition-colors leading-none">
                {directDepsCount}
              </h2>
              <p className="text-[11px] text-gray-500 dark:text-gray-400 mt-1 flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-blue-500 inline-block" />
                <span>Root level packages</span>
              </p>
            </div>
            <ArrowRight className="w-3.5 h-3.5 text-blue-400 dark:text-blue-500/70 group-hover:text-blue-600 dark:group-hover:text-blue-300 group-hover:translate-x-0.5 transition-all mb-0.5 shrink-0" />
          </div>
        </div>

        {/* Card 2: TRANSITIVE (Indigo Theme) */}
        <div className="bg-gradient-to-b from-indigo-50/40 via-white to-white dark:from-indigo-950/20 dark:via-[#111827] dark:to-[#111827] border border-indigo-100/90 dark:border-gray-800 hover:border-indigo-400 dark:hover:border-indigo-500 rounded-xl p-3.5 sm:p-4 shadow-2xs hover:shadow-md hover:shadow-indigo-500/5 hover:-translate-y-0.5 transition-all duration-200 min-h-[116px] flex flex-col justify-between group cursor-pointer">
          <div className="flex items-start justify-between gap-1.5">
            <div className="flex items-center gap-2 min-w-0 pr-1">
              <div className="w-7 h-7 rounded-lg bg-indigo-100/80 dark:bg-indigo-900/40 text-indigo-600 dark:text-indigo-400 flex items-center justify-center shrink-0 border border-indigo-200/50 dark:border-indigo-800/50 shadow-2xs">
                <GitFork className="w-3.5 h-3.5" />
              </div>
              <span className="text-[11px] font-bold uppercase tracking-tight text-gray-700 dark:text-gray-300 leading-snug">
                TRANSITIVE
              </span>
            </div>
            <div className="relative group/info shrink-0 -mr-1 -mt-0.5">
              <button
                type="button"
                className="p-1 rounded-full text-gray-400 hover:text-indigo-600 dark:hover:text-indigo-400 hover:bg-indigo-50 dark:hover:bg-indigo-950/40 transition-colors cursor-help"
                aria-label="Transitive Dependencies Info"
              >
                <Info className="w-3.5 h-3.5" />
              </button>
              <div className="absolute right-0 bottom-full mb-2 opacity-0 invisible group-hover/info:opacity-100 group-hover/info:visible transition-all duration-150 w-56 p-2.5 bg-gray-900 text-white text-[11px] normal-case font-normal rounded-lg shadow-xl z-50 pointer-events-none leading-relaxed">
                <div className="font-bold text-white mb-0.5">Transitive Dependencies</div>
                Indirect sub-dependencies pulled into the tree by top-level libraries.
                <div className="absolute top-full right-2 border-4 border-transparent border-t-gray-900" />
              </div>
            </div>
          </div>

          <div className="mt-3 flex items-end justify-between">
            <div>
              <h2 className="text-2xl font-black text-gray-900 dark:text-white group-hover:text-indigo-600 dark:group-hover:text-indigo-400 transition-colors leading-none">
                {transitiveDepsCount}
              </h2>
              <p className="text-[11px] text-gray-500 dark:text-gray-400 mt-1 flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-indigo-500 inline-block" />
                <span>Indirect tree packages</span>
              </p>
            </div>
            <ArrowRight className="w-3.5 h-3.5 text-indigo-400 dark:text-indigo-500/70 group-hover:text-indigo-600 dark:group-hover:text-indigo-300 group-hover:translate-x-0.5 transition-all mb-0.5 shrink-0" />
          </div>
        </div>

        {/* Card 3: MALICIOUS FLAGGED (Amber Theme) */}
        <div className="bg-gradient-to-b from-amber-50/40 via-white to-white dark:from-amber-950/20 dark:via-[#111827] dark:to-[#111827] border border-amber-100/90 dark:border-gray-800 hover:border-amber-400 dark:hover:border-amber-500 rounded-xl p-3.5 sm:p-4 shadow-2xs hover:shadow-md hover:shadow-amber-500/5 hover:-translate-y-0.5 transition-all duration-200 min-h-[116px] flex flex-col justify-between group cursor-pointer">
          <div className="flex items-start justify-between gap-1.5">
            <div className="flex items-center gap-2 min-w-0 pr-1">
              <div className="w-7 h-7 rounded-lg bg-amber-100/80 dark:bg-amber-900/40 text-amber-600 dark:text-amber-400 flex items-center justify-center shrink-0 border border-amber-200/50 dark:border-amber-800/50 shadow-2xs">
                <GitFork className="w-3.5 h-3.5" />
              </div>
              <span className="text-[11px] font-bold uppercase tracking-tight text-gray-700 dark:text-gray-300 leading-snug">
                MALICIOUS FLAGGED
              </span>
            </div>
            <div className="relative group/info shrink-0 -mr-1 -mt-0.5">
              <button
                type="button"
                className="p-1 rounded-full text-gray-400 hover:text-amber-600 dark:hover:text-amber-400 hover:bg-amber-50 dark:hover:bg-amber-950/40 transition-colors cursor-help"
                aria-label="Malicious Flagged Info"
              >
                <Info className="w-3.5 h-3.5" />
              </button>
              <div className="absolute right-0 bottom-full mb-2 opacity-0 invisible group-hover/info:opacity-100 group-hover/info:visible transition-all duration-150 w-56 p-2.5 bg-gray-900 text-white text-[11px] normal-case font-normal rounded-lg shadow-xl z-50 pointer-events-none leading-relaxed">
                <div className="font-bold text-white mb-0.5">Malicious / Critical Flagged</div>
                Components flagged with malicious behaviors or severe critical CVE advisories.
                <div className="absolute top-full right-2 border-4 border-transparent border-t-gray-900" />
              </div>
            </div>
          </div>

          <div className="mt-3 flex items-end justify-between">
            <div>
              <h2 className="text-2xl font-black text-amber-600 dark:text-amber-400 leading-none">
                {maliciousCount}
              </h2>
              <p className="text-[11px] text-amber-700 dark:text-amber-400/90 mt-1 flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-amber-500 inline-block animate-pulse" />
                <span>{maliciousCount} requiring patch</span>
              </p>
            </div>
            <ArrowRight className="w-3.5 h-3.5 text-amber-400 dark:text-amber-500/70 group-hover:text-amber-600 group-hover:translate-x-0.5 transition-all mb-0.5 shrink-0" />
          </div>
        </div>

        {/* Card 4: TYPOSQUATS (Rose Theme) */}
        <div className="bg-gradient-to-b from-rose-50/40 via-white to-white dark:from-rose-950/20 dark:via-[#111827] dark:to-[#111827] border border-rose-100/90 dark:border-gray-800 hover:border-rose-400 dark:hover:border-rose-500 rounded-xl p-3.5 sm:p-4 shadow-2xs hover:shadow-md hover:shadow-rose-500/5 hover:-translate-y-0.5 transition-all duration-200 min-h-[116px] flex flex-col justify-between group cursor-pointer">
          <div className="flex items-start justify-between gap-1.5">
            <div className="flex items-center gap-2 min-w-0 pr-1">
              <div className="w-7 h-7 rounded-lg bg-rose-100/80 dark:bg-rose-900/40 text-rose-600 dark:text-rose-400 flex items-center justify-center shrink-0 border border-rose-200/50 dark:border-rose-800/50 shadow-2xs">
                <GitFork className="w-3.5 h-3.5" />
              </div>
              <span className="text-[11px] font-bold uppercase tracking-tight text-gray-700 dark:text-gray-300 leading-snug">
                TYPOSQUATS
              </span>
            </div>
            <div className="relative group/info shrink-0 -mr-1 -mt-0.5">
              <button
                type="button"
                className="p-1 rounded-full text-gray-400 hover:text-rose-600 dark:hover:text-rose-400 hover:bg-rose-50 dark:hover:bg-rose-950/40 transition-colors cursor-help"
                aria-label="Typosquats Info"
              >
                <Info className="w-3.5 h-3.5" />
              </button>
              <div className="absolute right-0 bottom-full mb-2 opacity-0 invisible group-hover/info:opacity-100 group-hover/info:visible transition-all duration-150 w-56 p-2.5 bg-gray-900 text-white text-[11px] normal-case font-normal rounded-lg shadow-xl z-50 pointer-events-none leading-relaxed">
                <div className="font-bold text-white mb-0.5">Typosquat Detections</div>
                Packages exhibiting near-match naming collision with verified ecosystem components.
                <div className="absolute top-full right-2 border-4 border-transparent border-t-gray-900" />
              </div>
            </div>
          </div>

          <div className="mt-3 flex items-end justify-between">
            <div>
              <h2 className="text-2xl font-black text-gray-900 dark:text-white group-hover:text-rose-600 dark:group-hover:text-rose-400 transition-colors leading-none">
                {typosquatCount}
              </h2>
              <p className="text-[11px] text-gray-500 dark:text-gray-400 mt-1 flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-rose-500 inline-block" />
                <span>0 suspicious packages</span>
              </p>
            </div>
            <ArrowRight className="w-3.5 h-3.5 text-rose-400 dark:text-rose-500/70 group-hover:text-rose-600 dark:group-hover:text-rose-300 group-hover:translate-x-0.5 transition-all mb-0.5 shrink-0" />
          </div>
        </div>

        {/* Card 5: UNSIGNED ARTEFACTS (Sky Theme) */}
        <div className="bg-gradient-to-b from-sky-50/40 via-white to-white dark:from-sky-950/20 dark:via-[#111827] dark:to-[#111827] border border-sky-100/90 dark:border-gray-800 hover:border-sky-400 dark:hover:border-sky-500 rounded-xl p-3.5 sm:p-4 shadow-2xs hover:shadow-md hover:shadow-sky-500/5 hover:-translate-y-0.5 transition-all duration-200 min-h-[116px] flex flex-col justify-between group cursor-pointer">
          <div className="flex items-start justify-between gap-1.5">
            <div className="flex items-center gap-2 min-w-0 pr-1">
              <div className="w-7 h-7 rounded-lg bg-sky-100/80 dark:bg-sky-900/40 text-sky-600 dark:text-sky-400 flex items-center justify-center shrink-0 border border-sky-200/50 dark:border-sky-800/50 shadow-2xs">
                <GitFork className="w-3.5 h-3.5" />
              </div>
              <span className="text-[11px] font-bold uppercase tracking-tight text-gray-700 dark:text-gray-300 leading-snug">
                UNSIGNED ARTEFACTS
              </span>
            </div>
            <div className="relative group/info shrink-0 -mr-1 -mt-0.5">
              <button
                type="button"
                className="p-1 rounded-full text-gray-400 hover:text-sky-600 dark:hover:text-sky-400 hover:bg-sky-50 dark:hover:bg-sky-950/40 transition-colors cursor-help"
                aria-label="Unsigned Artefacts Info"
              >
                <Info className="w-3.5 h-3.5" />
              </button>
              <div className="absolute right-0 bottom-full mb-2 opacity-0 invisible group-hover/info:opacity-100 group-hover/info:visible transition-all duration-150 w-56 p-2.5 bg-gray-900 text-white text-[11px] normal-case font-normal rounded-lg shadow-xl z-50 pointer-events-none leading-relaxed">
                <div className="font-bold text-white mb-0.5">Unsigned Artefacts</div>
                Packages lacking verified cryptographic provenance checksums or digital signatures.
                <div className="absolute top-full right-2 border-4 border-transparent border-t-gray-900" />
              </div>
            </div>
          </div>

          <div className="mt-3 flex items-end justify-between">
            <div>
              <h2 className="text-2xl font-black text-gray-900 dark:text-white group-hover:text-sky-600 dark:group-hover:text-sky-400 transition-colors leading-none">
                {unsignedCount}
              </h2>
              <p className="text-[11px] text-gray-500 dark:text-gray-400 mt-1 flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-sky-500 inline-block" />
                <span>Missing digital signatures</span>
              </p>
            </div>
            <ArrowRight className="w-3.5 h-3.5 text-sky-400 dark:text-sky-500/70 group-hover:text-sky-600 dark:group-hover:text-sky-300 group-hover:translate-x-0.5 transition-all mb-0.5 shrink-0" />
          </div>
        </div>
      </div>

      {/* 4 Detail Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        {/* Catalog Size */}
        <div className="bg-gradient-to-b from-blue-50/40 via-white to-white dark:from-blue-950/20 dark:via-[#111827] dark:to-[#111827] border border-blue-100/90 dark:border-gray-800 hover:border-blue-400 dark:hover:border-blue-500 rounded-xl p-3.5 sm:p-4 shadow-2xs hover:shadow-md hover:shadow-blue-500/5 hover:-translate-y-0.5 transition-all duration-200 flex flex-col justify-between group">
          <div className="flex items-center gap-2">
            <div className="w-7 h-7 rounded-lg bg-blue-100/80 dark:bg-blue-900/40 text-blue-600 dark:text-blue-400 flex items-center justify-center shrink-0 border border-blue-200/50 dark:border-blue-800/50 shadow-2xs">
              <Package className="w-3.5 h-3.5" />
            </div>
            <span className="text-[11px] font-bold uppercase tracking-tight text-gray-700 dark:text-gray-300 leading-snug">
              CATALOG SIZE
            </span>
          </div>
          <div className="mt-3">
            <h2 className="text-2xl font-black text-gray-900 dark:text-white leading-none">
              {catalogSize}
            </h2>
            <p className="text-[11px] text-gray-500 dark:text-gray-400 mt-1.5">
              Unique packages in latest completed scans
            </p>
          </div>
        </div>

        {/* Ecosystems */}
        <div className="bg-gradient-to-b from-indigo-50/40 via-white to-white dark:from-indigo-950/20 dark:via-[#111827] dark:to-[#111827] border border-indigo-100/90 dark:border-gray-800 hover:border-indigo-400 dark:hover:border-indigo-500 rounded-xl p-3.5 sm:p-4 shadow-2xs hover:shadow-md hover:shadow-indigo-500/5 hover:-translate-y-0.5 transition-all duration-200 flex flex-col justify-between group">
          <div className="flex items-center gap-2">
            <div className="w-7 h-7 rounded-lg bg-indigo-100/80 dark:bg-indigo-900/40 text-indigo-600 dark:text-indigo-400 flex items-center justify-center shrink-0 border border-indigo-200/50 dark:border-indigo-800/50 shadow-2xs">
              <Layers className="w-3.5 h-3.5" />
            </div>
            <span className="text-[11px] font-bold uppercase tracking-tight text-gray-700 dark:text-gray-300 leading-snug">
              ECOSYSTEMS
            </span>
          </div>
          <div className="mt-3">
            <h2 className="text-2xl font-black text-gray-900 dark:text-white leading-none">
              {ecosystemsCount}
            </h2>
            <p className="text-[11px] text-gray-500 dark:text-gray-400 mt-1.5">
              npm, Maven, PyPI, Go, and others detected
            </p>
          </div>
        </div>

        {/* Integrity Coverage */}
        <div className="bg-gradient-to-b from-emerald-50/40 via-white to-white dark:from-emerald-950/20 dark:via-[#111827] dark:to-[#111827] border border-emerald-100/90 dark:border-gray-800 hover:border-emerald-400 dark:hover:border-emerald-500 rounded-xl p-3.5 sm:p-4 shadow-2xs hover:shadow-md hover:shadow-emerald-500/5 hover:-translate-y-0.5 transition-all duration-200 flex flex-col justify-between group">
          <div className="flex items-center gap-2">
            <div className="w-7 h-7 rounded-lg bg-emerald-100/80 dark:bg-emerald-900/40 text-emerald-600 dark:text-emerald-400 flex items-center justify-center shrink-0 border border-emerald-200/50 dark:border-emerald-800/50 shadow-2xs">
              <FileCheck2 className="w-3.5 h-3.5" />
            </div>
            <span className="text-[11px] font-bold uppercase tracking-tight text-gray-700 dark:text-gray-300 leading-snug">
              INTEGRITY COVERAGE
            </span>
          </div>
          <div className="mt-3">
            <h2 className="text-2xl font-black text-emerald-600 dark:text-emerald-400 leading-none">
              {integrityCoverage}%
            </h2>
            <p className="text-[11px] text-emerald-700 dark:text-emerald-400/90 mt-1.5">
              Packages with a versioned Package URL (hash field not yet populated)
            </p>
          </div>
        </div>

        {/* Copyleft Packages */}
        <div className="bg-gradient-to-b from-amber-50/40 via-white to-white dark:from-amber-950/20 dark:via-[#111827] dark:to-[#111827] border border-amber-100/90 dark:border-gray-800 hover:border-amber-400 dark:hover:border-amber-500 rounded-xl p-3.5 sm:p-4 shadow-2xs hover:shadow-md hover:shadow-amber-500/5 hover:-translate-y-0.5 transition-all duration-200 flex flex-col justify-between group">
          <div className="flex items-center gap-2">
            <div className="w-7 h-7 rounded-lg bg-amber-100/80 dark:bg-amber-900/40 text-amber-600 dark:text-amber-400 flex items-center justify-center shrink-0 border border-amber-200/50 dark:border-amber-800/50 shadow-2xs">
              <Scale className="w-3.5 h-3.5" />
            </div>
            <span className="text-[11px] font-bold uppercase tracking-tight text-gray-700 dark:text-gray-300 leading-snug">
              COPYLEFT PACKAGES
            </span>
          </div>
          <div className="mt-3">
            <h2 className="text-2xl font-black text-gray-900 dark:text-white leading-none">
              {copyleftCount}
            </h2>
            <p className="text-[11px] text-gray-500 dark:text-gray-400 mt-1.5 leading-relaxed">
              Copyleft licenses (GPL/AGPL/SSPL) may require source disclosure if you distribute the combined work.
            </p>
          </div>
        </div>
      </div>

      {/* Trust Findings Panel */}
      <div className="bg-white dark:bg-[#111827] border border-gray-200 dark:border-gray-800 rounded-xl p-5 shadow-2xs space-y-4">
        {/* Header with Search and Risk Filter */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <div className="flex items-center gap-1.5">
              <h2 className="text-sm sm:text-base font-bold text-gray-900 dark:text-white">Trust findings</h2>
              <Info className="w-3.5 h-3.5 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 cursor-pointer" />
            </div>
            <p className="text-xs text-gray-500 dark:text-gray-400 mt-0.5">
              {filteredFindings.length} of {allFindings.length} findings from live inventory + CVE feed
            </p>
          </div>

          <div className="flex items-center gap-2.5">
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-gray-400 absolute left-2.5 top-1/2 -translate-y-1/2 pointer-events-none" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search package, project, CVE..."
                className="w-48 sm:w-60 pl-8 pr-3 py-1.5 rounded-lg bg-gray-50 dark:bg-gray-800 border border-gray-200 dark:border-gray-700 text-xs text-gray-900 dark:text-gray-200 placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:border-blue-500"
              />
            </div>

            <div className="relative">
              <select
                value={riskFilter}
                onChange={(e) => setRiskFilter(e.target.value)}
                className="appearance-none pl-3 pr-8 py-1.5 rounded-lg bg-gray-50 dark:bg-gray-800 border border-gray-200 dark:border-gray-700 text-xs text-gray-800 dark:text-gray-300 font-medium focus:outline-none focus:border-blue-500 cursor-pointer"
              >
                <option value="all">All risk</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
              <ChevronDown className="w-3.5 h-3.5 text-gray-400 absolute right-2.5 top-1/2 -translate-y-1/2 pointer-events-none" />
            </div>
          </div>
        </div>

        {/* Filter Tabs / Pills */}
        <div className="flex items-center gap-2 flex-wrap border-b border-gray-200 dark:border-gray-800/80 pb-3">
          <button
            type="button"
            onClick={() => setActiveTab('all')}
            className={`px-3 py-1 rounded-full text-xs font-semibold transition-colors cursor-pointer ${
              activeTab === 'all'
                ? 'bg-red-50 dark:bg-[#2a131a] border border-red-500 dark:border-[#ef4444] text-red-600 dark:text-[#f87171]'
                : 'text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white hover:bg-gray-100 dark:hover:bg-gray-800/60'
            }`}
          >
            All {allFindings.length}
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('copyleft')}
            className={`px-3 py-1 rounded-full text-xs font-semibold transition-colors cursor-pointer ${
              activeTab === 'copyleft'
                ? 'bg-red-50 dark:bg-[#2a131a] border border-red-500 dark:border-[#ef4444] text-red-600 dark:text-[#f87171]'
                : 'text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white hover:bg-gray-100 dark:hover:bg-gray-800/60'
            }`}
          >
            Copyleft {copyleftCount}
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('transitive')}
            className={`px-3 py-1 rounded-full text-xs font-semibold transition-colors cursor-pointer ${
              activeTab === 'transitive'
                ? 'bg-red-50 dark:bg-[#2a131a] border border-red-500 dark:border-[#ef4444] text-red-600 dark:text-[#f87171]'
                : 'text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white hover:bg-gray-100 dark:hover:bg-gray-800/60'
            }`}
          >
            Transitive CVE {transitiveCveCount}
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('unsigned')}
            className={`px-3 py-1 rounded-full text-xs font-semibold transition-colors cursor-pointer ${
              activeTab === 'unsigned'
                ? 'bg-red-50 dark:bg-[#2a131a] border border-red-500 dark:border-[#ef4444] text-red-600 dark:text-[#f87171]'
                : 'text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white hover:bg-gray-100 dark:hover:bg-gray-800/60'
            }`}
          >
            Unsigned {unsignedCount}
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('malicious')}
            className={`px-3 py-1 rounded-full text-xs font-semibold transition-colors cursor-pointer ${
              activeTab === 'malicious'
                ? 'bg-red-50 dark:bg-[#2a131a] border border-red-500 dark:border-[#ef4444] text-red-600 dark:text-[#f87171]'
                : 'text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white hover:bg-gray-100 dark:hover:bg-gray-800/60'
            }`}
          >
            Malicious / critical {maliciousCount}
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('typosquat')}
            className={`px-3 py-1 rounded-full text-xs font-semibold transition-colors cursor-pointer ${
              activeTab === 'typosquat'
                ? 'bg-red-50 dark:bg-[#2a131a] border border-red-500 dark:border-[#ef4444] text-red-600 dark:text-[#f87171]'
                : 'text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white hover:bg-gray-100 dark:hover:bg-gray-800/60'
            }`}
          >
            Typosquat {typosquatCount}
          </button>
        </div>

        {/* Content Area: Empty State or Findings Table */}
        {filteredFindings.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 px-4 text-center">
            <Fingerprint className="w-10 h-10 text-gray-400 dark:text-gray-500 stroke-1 mb-3" />
            <h3 className="text-sm font-semibold text-gray-900 dark:text-white">No supply-chain findings yet</h3>
            <p className="text-xs text-gray-500 dark:text-gray-400 max-w-md mt-1.5 leading-relaxed">
              Latest completed scans have no copyleft, typosquat, unsigned, or critical-CVE issues in the current catalog.
            </p>
            <button
              type="button"
              onClick={() => navigate('/security-scans/new')}
              className="px-5 py-2 rounded-lg bg-[#ef4444] hover:bg-[#dc2626] text-white text-xs font-semibold mt-4 transition-colors cursor-pointer shadow-xs"
            >
              Launch scan
            </button>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-gray-50 dark:bg-[#0b0f19] text-gray-500 dark:text-gray-400 font-semibold border-b border-gray-200 dark:border-gray-800 uppercase tracking-wider text-[11px]">
                <tr>
                  <th className="py-2.5 px-3">Category</th>
                  <th className="py-2.5 px-3">Package</th>
                  <th className="py-2.5 px-3">Version</th>
                  <th className="py-2.5 px-3">Risk</th>
                  <th className="py-2.5 px-3">Details / Evidence</th>
                  <th className="py-2.5 px-3">Project</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200 dark:divide-gray-800/60 text-gray-800 dark:text-gray-200">
                {filteredFindings.map((f) => (
                  <tr key={f.id} className="hover:bg-gray-50 dark:hover:bg-gray-800/30 transition-colors">
                    <td className="py-2.5 px-3">
                      <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300 border border-gray-200 dark:border-gray-700">
                        {f.category}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 font-semibold text-gray-900 dark:text-white">{f.package}</td>
                    <td className="py-2.5 px-3 font-mono text-gray-500 dark:text-gray-400">{f.version}</td>
                    <td className="py-2.5 px-3">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          f.risk === 'Critical'
                            ? 'bg-red-50 dark:bg-red-950/80 text-red-700 dark:text-red-300 border border-red-200 dark:border-red-800'
                            : f.risk === 'High'
                            ? 'bg-orange-50 dark:bg-orange-950/80 text-orange-700 dark:text-orange-300 border border-orange-200 dark:border-orange-800'
                            : 'bg-yellow-50 dark:bg-yellow-950/80 text-yellow-700 dark:text-yellow-300 border border-yellow-200 dark:border-yellow-800'
                        }`}
                      >
                        {f.risk}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-gray-600 dark:text-gray-400 max-w-md truncate" title={f.details}>
                      {f.details}
                    </td>
                    <td className="py-2.5 px-3 text-gray-600 dark:text-gray-400">{f.project}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};

export default SupplyChain;
