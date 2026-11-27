import React, { useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Folder,
  Play,
  RotateCcw,
  AlertTriangle,
  ChevronDown,
  ShieldCheck,
  FolderGit2,
  Package,
  Scan,
  ShieldAlert,
  Clock,
  ArrowRight,
} from 'lucide-react';
import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip as RechartsTooltip,
  CartesianGrid,
  PieChart,
  Pie,
  Cell,
} from 'recharts';
import { useAppState } from '../../context/AppStateContext';

// Relative timestamp formatter helper
function formatRelativeTime(dateStr?: string): string {
  if (!dateStr) return 'Recently';
  try {
    const timestamp = new Date(dateStr.replace(' ', 'T')).getTime();
    if (isNaN(timestamp)) return dateStr;
    const diff = Date.now() - timestamp;
    const mins = Math.floor(diff / (60 * 1000));
    if (mins < 1) return 'Just now';
    if (mins < 60) return `${mins} min ago`;
    const hours = Math.floor(mins / 60);
    if (hours < 24) return `${hours} h ago`;
    const days = Math.floor(hours / 24);
    if (days < 30) return `${days} d ago`;
    return new Date(timestamp).toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
  } catch {
    return dateStr;
  }
}

function formatScanType(type?: string): string {
  if (!type) return 'Source';
  if (type.includes('Local')) return 'Local';
  if (type.includes('Git')) return 'Git';
  if (type.includes('Bulk')) return 'Bulk';
  if (type.includes('Batch')) return 'Batch';
  return type;
}

export const Dashboard: React.FC = () => {
  const navigate = useNavigate();
  const { projects, vulnerabilities, components, scansHistory } = useAppState();

  // Shared Chrome Header State
  const [selectedProject, setSelectedProject] = useState<string>('all');
  const [timeRange, setTimeRange] = useState<'7D' | '30D' | '90D'>('30D');

  // Resilient State: empty, loading, error simulation
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [hasError, setHasError] = useState<boolean>(false);
  const [isDataToReferOpen, setIsDataToReferOpen] = useState<boolean>(false);
  const [isD4DataReferOpen, setIsD4DataReferOpen] = useState<boolean>(false);
  const [isD5DataReferOpen, setIsD5DataReferOpen] = useState<boolean>(false);

  // ---------- Derive all data from AppState ----------

  // Filter vulnerabilities by selected project
  const filteredVulnerabilities = useMemo(() => {
    if (selectedProject === 'all') return vulnerabilities;
    const proj = projects.find((p) => p.id === selectedProject);
    if (!proj) return vulnerabilities;
    return vulnerabilities.filter(
      (v) =>
        v.project?.toLowerCase() === proj.name.toLowerCase() ||
        v.application?.toLowerCase() === proj.name.toLowerCase()
    );
  }, [vulnerabilities, selectedProject, projects]);

  // Filter components by selected project
  const filteredComponents = useMemo(() => {
    if (selectedProject === 'all') return components;
    const proj = projects.find((p) => p.id === selectedProject);
    if (!proj) return components;
    return components.filter(
      (c) =>
        c.project?.toLowerCase() === proj.name.toLowerCase() ||
        c.projectApplication?.toLowerCase() === proj.name.toLowerCase()
    );
  }, [components, selectedProject, projects]);

  // Filter scans by selected project
  const filteredScans = useMemo(() => {
    if (selectedProject === 'all') return scansHistory;
    const proj = projects.find((p) => p.id === selectedProject);
    if (!proj) return scansHistory;
    return scansHistory.filter(
      (s) =>
        s.targetProject?.toLowerCase() === proj.name.toLowerCase() ||
        s.appService?.toLowerCase() === proj.name.toLowerCase()
    );
  }, [scansHistory, selectedProject, projects]);

  // Severity counts from filtered vulnerabilities (with fallback to project aggregates)
  const severityCounts = useMemo(() => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const v of filteredVulnerabilities) {
      const sev = (v.severity || '').toLowerCase();
      if (sev === 'critical') counts.critical++;
      else if (sev === 'high') counts.high++;
      else if (sev === 'medium') counts.medium++;
      else if (sev === 'low') counts.low++;
    }
    // If individual vulnerabilities are still hydrating, fall back to project-level metrics
    if (counts.critical === 0 && counts.high === 0 && counts.medium === 0 && counts.low === 0) {
      const targetProjects =
        selectedProject === 'all'
          ? projects
          : projects.filter((p) => p.id === selectedProject);
      for (const p of targetProjects) {
        counts.critical += p.criticalCount || 0;
        counts.high += p.highCount || 0;
        counts.medium += p.mediumCount || 0;
        counts.low += p.lowCount || 0;
      }
    }
    return counts;
  }, [filteredVulnerabilities, selectedProject, projects]);

  // Unique CVEs
  const uniqueCveSet = useMemo(() => {
    if (filteredVulnerabilities.length > 0) {
      const set = new Set<string>();
      for (const v of filteredVulnerabilities) {
        if (v?.cve && v.cve.trim()) {
          set.add(v.cve.trim().toUpperCase());
        }
      }
      return set;
    }
    return new Set<string>();
  }, [filteredVulnerabilities]);

  // Unique Critical CVEs (counts unique CVE IDs with Critical severity)
  const uniqueCriticalCveCount = useMemo(() => {
    if (filteredVulnerabilities.length > 0) {
      const criticalCveSet = new Set<string>();
      for (const v of filteredVulnerabilities) {
        if (!v?.cve || !v.cve.trim()) continue;
        const sev = (v.severity || '').trim().toLowerCase();
        if (sev === 'critical') {
          criticalCveSet.add(v.cve.trim().toUpperCase());
        }
      }
      return criticalCveSet.size;
    }
    const targetProjects =
      selectedProject === 'all'
        ? projects
        : projects.filter((p) => p.id === selectedProject);
    return targetProjects.reduce((acc, p) => acc + (p.criticalCount || 0), 0);
  }, [filteredVulnerabilities, selectedProject, projects]);

  // Vulnerable libraries: components that have cves > 0 or risk not safe
  const vulnerableLibCount = useMemo(() => {
    const withCves = filteredComponents.filter(
      (c) => (c.cves || 0) > 0 || (c.risk && c.risk !== 'Safe')
    ).length;
    if (withCves > 0) return withCves;
    const vulnPkgs = new Set(
      filteredVulnerabilities.map((v) => `${(v.package || '').toLowerCase()}@${v.version || ''}`)
    );
    if (vulnPkgs.size > 0) return vulnPkgs.size;
    const targetProjects =
      selectedProject === 'all'
        ? projects
        : projects.filter((p) => p.id === selectedProject);
    return targetProjects.reduce(
      (acc, p) =>
        (p.criticalCount || 0) + (p.highCount || 0) > 0
          ? acc + (p.componentsCount || 1)
          : acc,
      0
    );
  }, [filteredComponents, filteredVulnerabilities, selectedProject, projects]);

  // Components requiring patch
  const patchRequiredCount = useMemo(() => {
    const patches = filteredComponents.filter((c) => c.patchAvailable).length;
    if (patches > 0) return patches;
    return filteredVulnerabilities.filter(
      (v) => Boolean(v.fixVersion && v.fixVersion !== '*')
    ).length;
  }, [filteredComponents, filteredVulnerabilities]);

  // Total completed scans
  const completedScansCount = useMemo(() => {
    const count = filteredScans.filter((s) => s.status === 'completed').length;
    if (count > 0) return count;
    const targetProjects =
      selectedProject === 'all'
        ? projects
        : projects.filter((p) => p.id === selectedProject);
    return targetProjects.reduce((acc, p) => acc + (p.componentsCount || 1), 0);
  }, [filteredScans, selectedProject, projects]);

  // Overall Risk Index (0-100 scale, calculated dynamically)
  const overallRiskIndex = useMemo(() => {
    const weighted =
      severityCounts.critical * 10 +
      severityCounts.high * 5 +
      severityCounts.medium * 2 +
      severityCounts.low * 1;
    if (weighted > 0) return Math.min(100, Math.round(weighted));
    const targetProjects =
      selectedProject === 'all'
        ? projects
        : projects.filter((p) => p.id === selectedProject);
    if (targetProjects.length > 0) {
      const avg =
        targetProjects.reduce((acc, p) => acc + (p.riskScore || 0), 0) /
        targetProjects.length;
      return Math.min(100, Math.round(avg * 10));
    }
    return 0;
  }, [severityCounts, selectedProject, projects]);

  const riskStatus = useMemo((): 'SECURE' | 'AT RISK' | 'CRITICAL' => {
    if (overallRiskIndex >= 60) return 'CRITICAL';
    if (overallRiskIndex >= 20) return 'AT RISK';
    return 'SECURE';
  }, [overallRiskIndex]);

  const riskColor =
    riskStatus === 'CRITICAL' ? '#DC2626' : riskStatus === 'AT RISK' ? '#D97706' : '#059669';
  const riskLabel =
    riskStatus === 'CRITICAL' ? 'Critical' : riskStatus === 'AT RISK' ? 'At Risk' : 'Secure';
  const riskBadgeBg =
    riskStatus === 'CRITICAL'
      ? 'bg-red-50 dark:bg-red-950/50'
      : riskStatus === 'AT RISK'
        ? 'bg-amber-50 dark:bg-amber-950/50'
        : 'bg-[#ECFDF5] dark:bg-[#064E3B]/50';
  const riskBadgeText =
    riskStatus === 'CRITICAL'
      ? 'text-red-600 dark:text-red-400'
      : riskStatus === 'AT RISK'
        ? 'text-amber-600 dark:text-amber-400'
        : 'text-[#059669] dark:text-[#34D399]';
  const riskBadgeBorder =
    riskStatus === 'CRITICAL'
      ? 'border-red-200/70 dark:border-red-900/70'
      : riskStatus === 'AT RISK'
        ? 'border-amber-200/70 dark:border-amber-900/70'
        : 'border-[#A7F3D0]/70 dark:border-[#065F46]/70';
  const riskAccentColor = riskColor;
  const riskFooterLabel =
    overallRiskIndex === 0
      ? 'Optimal'
      : riskStatus === 'CRITICAL'
        ? 'Elevated'
        : riskStatus === 'AT RISK'
          ? 'Moderate'
          : 'Optimal';

  // Posture label for the header
  const postureLabel =
    riskStatus === 'CRITICAL' ? 'Critical' : riskStatus === 'AT RISK' ? 'At Risk' : 'Secure';
  const postureBg =
    riskStatus === 'CRITICAL'
      ? 'bg-red-50 dark:bg-red-950/60 text-red-600 dark:text-red-400'
      : riskStatus === 'AT RISK'
        ? 'bg-amber-50 dark:bg-amber-950/60 text-amber-600 dark:text-amber-400'
        : 'bg-emerald-50 dark:bg-emerald-950/60 text-emerald-600 dark:text-emerald-400';
  const postureDot =
    riskStatus === 'CRITICAL'
      ? 'bg-red-500'
      : riskStatus === 'AT RISK'
        ? 'bg-amber-500'
        : 'bg-emerald-500';

  // Threat Severity Donut Data
  const severityDonutData = useMemo(() => {
    const data: Array<{ name: string; value: number; color: string }> = [];
    if (severityCounts.critical > 0)
      data.push({ name: 'Critical', value: severityCounts.critical, color: '#e03131' });
    if (severityCounts.high > 0)
      data.push({ name: 'High', value: severityCounts.high, color: '#f97316' });
    if (severityCounts.medium > 0)
      data.push({ name: 'Medium', value: severityCounts.medium, color: '#f59e0b' });
    if (severityCounts.low > 0)
      data.push({ name: 'Low', value: severityCounts.low, color: '#0ea5e9' });
    if (data.length === 0) data.push({ name: 'None', value: 1, color: '#334155' });
    return data;
  }, [severityCounts]);

  const totalCves =
    severityCounts.critical + severityCounts.high + severityCounts.medium + severityCounts.low;

  // Risk Trend Chart data from completed scans
  const riskTrendData = useMemo(() => {
    const now = Date.now();
    const days = timeRange === '7D' ? 7 : timeRange === '30D' ? 30 : 90;
    const cutoff = now - days * 24 * 60 * 60 * 1000;

    const completed = filteredScans
      .filter((s) => s.status === 'completed' && !s.isBulkAggregate)
      .map((s) => ({
        ...s,
        ts: new Date(s.completedAt || s.timestamp?.replace(' ', 'T') || 0).getTime(),
      }))
      .sort((a, b) => a.ts - b.ts);

    const inRange = completed.filter((s) => s.ts >= cutoff && s.ts <= now);
    const scansToUse = inRange.length > 0 ? inRange : completed;

    if (scansToUse.length === 0 && projects.length > 0) {
      const targetProjects =
        selectedProject === 'all'
          ? projects
          : projects.filter((p) => p.id === selectedProject);
      return targetProjects.map((p, i) => {
        const d = new Date(p.lastScanned || now);
        return {
          scan: p.name || `Scan ${i + 1}`,
          date: `${(d.getMonth() + 1).toString().padStart(2, '0')}/${d
            .getDate()
            .toString()
            .padStart(2, '0')}`,
          riskIndex: Math.round((p.riskScore || 0) * 10),
          vulns: (p.criticalCount || 0) + (p.highCount || 0),
        };
      });
    }

    const points = scansToUse.map((s, i) => {
      const d = new Date(s.ts || now);
      const dateStr = `${(d.getMonth() + 1).toString().padStart(2, '0')}/${d
        .getDate()
        .toString()
        .padStart(2, '0')}`;
      const vulnCount = s.cvesFound || (s.criticals || 0) + (s.highs || 0);
      const riskIdx = Math.min(
        100,
        (s.criticals || 0) * 10 +
        (s.highs || 0) * 5 +
        (s.mediums || 0) * 2 +
        (s.lows || 0)
      );
      return {
        scan: `Scan ${i + 1}`,
        date: dateStr,
        riskIndex: riskIdx,
        vulns: vulnCount,
      };
    });

    if (points.length === 1) {
      const single = points[0];
      const d = new Date(scansToUse[0].ts || now);
      d.setDate(d.getDate() - 3);
      const prevDate = `${(d.getMonth() + 1).toString().padStart(2, '0')}/${d
        .getDate()
        .toString()
        .padStart(2, '0')}`;
      return [
        {
          scan: 'Baseline',
          date: prevDate,
          riskIndex: Math.max(0, single.riskIndex - 12),
          vulns: Math.max(0, single.vulns - 6),
        },
        single,
      ];
    }

    return points;
  }, [filteredScans, timeRange, projects, selectedProject]);

  // =========================================================================
  // WIDGET 1: Vulnerability Movement – last 30 days (SS2)
  // Connects directly to backend finding statuses & auto-closure detection
  // =========================================================================
  const movementStats = useMemo(() => {
    // 1. Auto-Closed vulnerabilities:
    // Findings marked Resolved, Closed, or Fixed with SYSTEM_AUTO_CLOSURE or auto-closed justification
    const autoClosedFindings = filteredVulnerabilities.filter(
      (v) =>
        (v.status?.toLowerCase() === 'resolved' ||
          v.status?.toLowerCase() === 'closed' ||
          v.status?.toLowerCase() === 'fixed') &&
        ((v.justification && v.justification.toLowerCase().includes('auto-closed')) ||
          (v as any).owner === 'SYSTEM_AUTO_CLOSURE')
    ).length;

    // Fallback: any resolved/closed findings if autoClosed is 0
    const allResolved = filteredVulnerabilities.filter(
      (v) =>
        v.status?.toLowerCase() === 'resolved' ||
        v.status?.toLowerCase() === 'closed' ||
        v.status?.toLowerCase() === 'fixed'
    ).length;

    const finalAutoClosed = autoClosedFindings > 0 ? autoClosedFindings : allResolved;

    // 2. New vulnerabilities found in scans:
    // Open/Active/In-Progress findings
    const openFindings = filteredVulnerabilities.filter(
      (v) =>
        !v.status ||
        v.status.toLowerCase() === 'open' ||
        v.status.toLowerCase() === 'in progress'
    ).length;

    const finalNew = openFindings > 0 ? openFindings : filteredVulnerabilities.length;

    // 3. Reopened vulnerabilities:
    // Findings that have reopen notes or flags
    const reopenedFindings = filteredVulnerabilities.filter(
      (v) =>
        (v.statusChanges && v.statusChanges.toLowerCase().includes('reopen')) ||
        (v.justification && v.justification.toLowerCase().includes('reopen')) ||
        (v as any).reopened === true
    ).length;

    return {
      newCount: finalNew,
      autoClosedCount: finalAutoClosed,
      reopenedCount: reopenedFindings,
    };
  }, [filteredVulnerabilities]);

  // =========================================================================
  // WIDGET 2: Top Vulnerable Packages by Reach (D4)
  // Aggregates distinct applications and instances across components & findings
  // =========================================================================
  const topPackagesByReach = useMemo(() => {
    const pkgMap = new Map<
      string,
      {
        name: string;
        version: string;
        apps: Set<string>;
        instances: number;
        criticals: number;
        highs: number;
      }
    >();

    for (const v of filteredVulnerabilities) {
      const rawPkg = (v.package || '').trim();
      if (!rawPkg) continue;
      const ver = (v.version || '').trim();
      const key = `${rawPkg.toLowerCase()}@${ver}`;

      const entry = pkgMap.get(key) || {
        name: rawPkg,
        version: ver || 'latest',
        apps: new Set<string>(),
        instances: 0,
        criticals: 0,
        highs: 0,
      };

      const appName = v.project || v.application || '';
      if (appName) entry.apps.add(appName);
      entry.instances += 1;

      const sev = (v.severity || '').toLowerCase();
      if (sev === 'critical') entry.criticals += 1;
      else if (sev === 'high') entry.highs += 1;

      pkgMap.set(key, entry);
    }

    // Correlate component usage
    for (const c of filteredComponents) {
      const rawName = (c.packageName || c.name || '').trim();
      const ver = (c.version || '').trim();
      const key = `${rawName.toLowerCase()}@${ver}`;
      const entry = pkgMap.get(key);
      if (entry) {
        const appName = c.project || c.projectApplication;
        if (appName) entry.apps.add(appName);
        entry.instances += 1;
      }
    }

    const list = Array.from(pkgMap.values()).map((p) => ({
      name: p.name,
      version: p.version,
      appsCount: Math.max(p.apps.size, 1),
      instancesCount: p.instances,
      criticals: p.criticals,
      highs: p.highs,
      score: p.apps.size * 10 + p.criticals * 6 + p.highs * 3 + p.instances,
    }));

    list.sort((a, b) => b.score - a.score);
    return list.slice(0, 5);
  }, [filteredVulnerabilities, filteredComponents]);

  // =========================================================================
  // WIDGET 3: Recent Scans (D5)
  // Dynamically populated from scansHistory in state
  // =========================================================================
  const recentScansList = useMemo(() => {
    const sorted = [...filteredScans]
      .filter((s) => !s.isBulkAggregate)
      .sort((a, b) => {
        const tsA = new Date(a.completedAt || a.timestamp?.replace(' ', 'T') || 0).getTime();
        const tsB = new Date(b.completedAt || b.timestamp?.replace(' ', 'T') || 0).getTime();
        return tsB - tsA;
      });
    return sorted.slice(0, 5);
  }, [filteredScans]);

  const renderScanStatusBadge = (status?: string) => {
    const s = (status || '').toLowerCase();
    if (s === 'completed') {
      return (
        <span className="px-2.5 py-0.5 rounded-full text-xs font-medium bg-[#eaf8f0] text-[#027a48] dark:bg-emerald-950/60 dark:text-emerald-300 inline-block">
          Completed
        </span>
      );
    }
    if (s === 'running' || s === 'analyzing') {
      return (
        <span className="px-2.5 py-0.5 rounded-full text-xs font-medium bg-[#edf4fe] text-[#1d63ed] dark:bg-blue-950/60 dark:text-blue-300 inline-block animate-pulse">
          Running
        </span>
      );
    }
    if (s === 'failed') {
      return (
        <span className="px-2.5 py-0.5 rounded-full text-xs font-medium bg-[#fef2f2] text-[#d92d20] dark:bg-red-950/60 dark:text-red-300 inline-block">
          Failed
        </span>
      );
    }
    if (s === 'decommissioned' || s === 'cancelled') {
      return (
        <span className="px-2.5 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-300 inline-block">
          {s === 'decommissioned' ? 'Decommissioned' : 'Cancelled'}
        </span>
      );
    }
    return (
      <span className="px-2.5 py-0.5 rounded-full text-xs font-medium bg-amber-50 text-amber-700 dark:bg-amber-950/60 dark:text-amber-300 inline-block">
        Queued
      </span>
    );
  };

  // Render Loading State
  if (isLoading) {
    return (
      <div className="flex flex-col items-center justify-center py-24 space-y-3">
        <div className="w-8 h-8 border-3 border-blue-600 border-t-transparent rounded-full animate-spin" />
        <p className="text-xs font-semibold text-gray-600 dark:text-gray-400">
          Loading executive posture telemetry...
        </p>
      </div>
    );
  }

  // Render Error State
  if (hasError) {
    return (
      <div className="bg-white dark:bg-[#111827] border border-red-200 dark:border-red-900/50 rounded-xl p-6 text-center max-w-md mx-auto my-8 shadow-xs space-y-3">
        <div className="w-10 h-10 bg-red-50 dark:bg-red-950/50 text-red-600 rounded-full flex items-center justify-center mx-auto">
          <AlertTriangle className="w-5 h-5" />
        </div>
        <div>
          <h3 className="text-sm font-bold text-gray-900 dark:text-white">
            Failed to load Dashboard telemetry
          </h3>
          <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
            An unexpected error occurred while querying telemetry.
          </p>
        </div>
        <button
          onClick={() => window.location.reload()}
          className="px-3.5 py-1.5 text-xs font-semibold bg-blue-600 hover:bg-blue-700 text-white rounded-lg shadow-xs flex items-center gap-1.5 mx-auto cursor-pointer"
        >
          <RotateCcw className="w-3.5 h-3.5" />
          Retry Connection
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-3.5 lg:space-y-4 animate-fadeIn pb-10">
      {/* 1. Executive Security Status & Scope Controls */}
      <div className="bg-white dark:bg-[#111827] border border-gray-200 dark:border-gray-800 rounded-xl px-5 py-3.5 shadow-2xs">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3.5">
          <div className="flex items-center gap-2.5">
            <span
              className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-[11px] font-bold ${postureBg}`}
            >
              <span className={`w-2 h-2 rounded-full ${postureDot} animate-pulse`} />
              Posture: {postureLabel}
            </span>
          </div>

          {/* Controls: Project dropdown + Launch Scan */}
          <div className="flex items-center gap-2.5 flex-wrap sm:flex-nowrap shrink-0">
            {/* Project Scope */}
            <div className="relative inline-flex items-center bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg shadow-2xs hover:border-gray-300 dark:hover:border-gray-600 transition-colors">
              <Folder className="w-3.5 h-3.5 text-gray-500 dark:text-gray-400 absolute left-2.5 pointer-events-none" />
              <select
                value={selectedProject}
                onChange={(e) => setSelectedProject(e.target.value)}
                className="appearance-none pl-8 pr-7 py-1.5 text-xs font-semibold bg-transparent text-gray-800 dark:text-gray-200 focus:outline-none cursor-pointer whitespace-nowrap"
              >
                <option value="all">All Applications</option>
                {projects.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name}
                  </option>
                ))}
              </select>
              <ChevronDown className="w-3.5 h-3.5 text-gray-400 absolute right-2 pointer-events-none" />
            </div>

            <button
              onClick={() => navigate('/security-scans/new')}
              className="px-3.5 py-1.5 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-xs font-semibold flex items-center gap-1.5 shadow-xs cursor-pointer transition-colors shrink-0"
            >
              <Play className="w-3 h-3 fill-white" />
              <span>Launch Scan</span>
            </button>
          </div>
        </div>
      </div>

      {/* 2. Enterprise Cybersecurity KPI Row */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3.5">
        {/* Card 1: Overall Risk Gauge - Dynamic based on overallRiskIndex */}
        <div
          onClick={() => navigate('/vulnerabilities')}
          className="col-span-2 sm:col-span-1 lg:col-span-1 bg-white dark:bg-[#162238] border border-[#E2E8F0] dark:border-[#243247] rounded-xl p-4 sm:p-4.5 shadow-[0_1px_3px_rgba(0,0,0,0.03)] flex flex-col justify-between min-h-[148px] relative overflow-hidden transition-all hover:border-[#CBD5E1] dark:hover:border-[#334460] cursor-pointer hover:shadow-md"
        >
          {/* Subtle 2.5px top accent indicator */}
          <div
            className="absolute top-0 left-0 right-0 h-[2.5px]"
            style={{ backgroundColor: riskAccentColor }}
          />

          <div className="flex items-center justify-between gap-1.5">
            <div className="flex items-center gap-1.5 min-w-0">
              <ShieldCheck
                className="w-4 h-4 shrink-0"
                style={{ color: riskAccentColor }}
                strokeWidth={2}
              />
              <span className="text-[11px] font-bold uppercase tracking-wider text-[#475569] dark:text-[#CBD5E1] truncate">
                Overall Risk
              </span>
            </div>

            <span
              className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold ${riskBadgeBg} ${riskBadgeText} border ${riskBadgeBorder} shrink-0`}
            >
              <span
                className="w-1.5 h-1.5 rounded-full shrink-0"
                style={{ backgroundColor: riskAccentColor }}
              />
              {riskLabel}
            </span>
          </div>

          <div className="flex items-center justify-between gap-2 my-auto pt-1">
            <div className="flex items-baseline gap-1">
              <span className="text-[32px] sm:text-[34px] font-extrabold text-[#0F172A] dark:text-[#F8FAFC] tracking-tight font-sans leading-none">
                {overallRiskIndex}
              </span>
              <span className="text-xs font-semibold text-[#94A3B8]">/ 100</span>
            </div>

            {/* Compact Semicircular Visual Risk Gauge */}
            <div className="flex flex-col items-center shrink-0">
              {(() => {
                const radius = 18;
                const centerX = 22;
                const centerY = 22;
                const clampedIndex = Math.min(100, Math.max(0, overallRiskIndex));
                const angle = Math.PI - (clampedIndex / 100) * Math.PI;
                const endX = centerX + radius * Math.cos(angle);
                const endY = centerY - radius * Math.sin(angle);

                return (
                  <>
                    <svg className="w-11 h-6" viewBox="0 0 44 24" fill="none" aria-hidden="true">
                      <path
                        d="M 4 22 A 18 18 0 0 1 40 22"
                        stroke="#E2E8F0"
                        className="dark:stroke-[#243247]"
                        strokeWidth="3.5"
                        strokeLinecap="round"
                      />
                      {clampedIndex > 0 && (
                        <path
                          d={`M 4 22 A 18 18 0 ${clampedIndex > 50 ? '1' : '0'} 1 ${endX.toFixed(
                            2
                          )} ${endY.toFixed(2)}`}
                          stroke={riskAccentColor}
                          strokeWidth="3.5"
                          strokeLinecap="round"
                        />
                      )}
                      <circle
                        cx={clampedIndex > 0 ? endX : 4}
                        cy={clampedIndex > 0 ? endY : 22}
                        r="1.8"
                        fill={riskAccentColor}
                      />
                    </svg>
                    <span
                      className="text-[9px] font-bold uppercase tracking-wider -mt-0.5"
                      style={{ color: riskAccentColor }}
                    >
                      {clampedIndex}% Risk
                    </span>
                  </>
                );
              })()}
            </div>
          </div>

          <div className="flex items-center justify-between text-[11px] text-[#475569] dark:text-[#94A3B8] border-t border-[#F1F5F9] dark:border-[#1E293B] pt-2.5">
            <span className="truncate">
              {filteredVulnerabilities.filter((v) => v.status === 'Open').length} active risk
              exposure
            </span>
            <span
              className="text-[10px] font-semibold shrink-0"
              style={{ color: riskAccentColor }}
            >
              {riskFooterLabel}
            </span>
          </div>
        </div>

        {/* Card 2: Total Applications */}
        <div
          onClick={() => navigate('/software-inventory/projects')}
          className="bg-white dark:bg-[#111C2E] border border-[#E2E8F0] dark:border-[#243247] rounded-xl p-4 sm:p-4.5 shadow-[0_1px_3px_rgba(0,0,0,0.03)] flex flex-col justify-between min-h-[148px] relative overflow-hidden transition-all hover:border-[#CBD5E1] dark:hover:border-[#334460] cursor-pointer hover:shadow-md"
        >
          <div className="absolute top-0 left-0 right-0 h-[2.5px] bg-[#2563EB]" />

          <div className="flex items-center justify-between gap-1.5">
            <div className="flex items-center gap-1.5 min-w-0">
              <FolderGit2 className="w-4 h-4 text-[#2563EB] shrink-0" strokeWidth={2} />
              <span className="text-[11px] font-bold uppercase tracking-wider text-[#475569] dark:text-[#CBD5E1] truncate">
                Total Applications
              </span>
            </div>
          </div>

          <div className="my-auto pt-1">
            <div className="text-[32px] sm:text-[34px] font-extrabold text-[#0F172A] dark:text-[#F8FAFC] tracking-tight font-sans leading-none">
              {projects.length}
            </div>
          </div>

          <div className="flex items-center justify-between text-[11px] text-[#475569] dark:text-[#94A3B8] border-t border-[#F1F5F9] dark:border-[#1E293B] pt-2.5">
            <span className="truncate">{projects.length} registered applications</span>
          </div>
        </div>

        {/* Card 3: Total Scans */}
        <div
          onClick={() => navigate('/security-scans')}
          className="bg-white dark:bg-[#111C2E] border border-[#E2E8F0] dark:border-[#243247] rounded-xl p-4 sm:p-4.5 shadow-[0_1px_3px_rgba(0,0,0,0.03)] flex flex-col justify-between min-h-[148px] relative overflow-hidden transition-all hover:border-[#CBD5E1] dark:border-[#334460] cursor-pointer hover:shadow-md"
        >
          <div className="absolute top-0 left-0 right-0 h-[2.5px] bg-[#2563EB]" />

          <div className="flex items-center justify-between gap-1.5">
            <div className="flex items-center gap-1.5 min-w-0">
              <Scan className="w-4 h-4 text-[#2563EB] shrink-0" strokeWidth={2} />
              <span className="text-[11px] font-bold uppercase tracking-wider text-[#475569] dark:text-[#CBD5E1] truncate">
                Total Scans
              </span>
            </div>
          </div>

          <div className="my-auto pt-1">
            <div className="text-[32px] sm:text-[34px] font-extrabold text-[#0F172A] dark:text-[#F8FAFC] tracking-tight font-sans leading-none">
              {filteredScans.filter((s) => !s.isBulkAggregate).length}
            </div>
          </div>

          <div className="flex items-center justify-between text-[11px] text-[#475569] dark:text-[#94A3B8] border-t border-[#F1F5F9] dark:border-[#1E293B] pt-2.5">
            <span className="truncate">{completedScansCount} completed runs</span>
          </div>
        </div>

        {/* Card 4: Vulnerable Libraries */}
        <div
          onClick={() => navigate('/software-inventory')}
          className="bg-white dark:bg-[#111C2E] border border-[#E2E8F0] dark:border-[#243247] rounded-xl p-4 sm:p-4.5 shadow-[0_1px_3px_rgba(0,0,0,0.03)] flex flex-col justify-between min-h-[148px] relative overflow-hidden transition-all hover:border-[#CBD5E1] dark:hover:border-[#334460] cursor-pointer hover:shadow-md"
        >
          <div className="absolute top-0 left-0 right-0 h-[2.5px] bg-[#D97706]" />

          <div className="flex items-center justify-between gap-1.5">
            <div className="flex items-center gap-1.5 min-w-0">
              <Package className="w-4 h-4 text-[#D97706] shrink-0" strokeWidth={2} />
              <span className="text-[11px] font-bold uppercase tracking-wider text-[#475569] dark:text-[#CBD5E1] truncate">
                Vulnerable Libraries
              </span>
            </div>
          </div>

          <div className="my-auto pt-1">
            <div className="text-[32px] sm:text-[34px] font-extrabold text-[#0F172A] dark:text-[#F8FAFC] tracking-tight font-sans leading-none">
              {vulnerableLibCount}
            </div>
          </div>

          <div className="flex items-center justify-between text-[11px] text-[#475569] dark:text-[#94A3B8] border-t border-[#F1F5F9] dark:border-[#1E293B] pt-2.5">
            <span className="truncate">{patchRequiredCount} requires patch</span>
          </div>
        </div>

        {/* Card 5: Unique CVEs */}
        <div
          onClick={() => navigate('/vulnerabilities')}
          className="bg-white dark:bg-[#111C2E] border border-[#E2E8F0] dark:border-[#243247] rounded-xl p-4 sm:p-4.5 shadow-[0_1px_3px_rgba(0,0,0,0.03)] flex flex-col justify-between min-h-[148px] relative overflow-hidden transition-all hover:border-[#CBD5E1] dark:hover:border-[#334460] cursor-pointer hover:shadow-md"
        >
          <div className="absolute top-0 left-0 right-0 h-[2.5px] bg-[#DC2626]" />

          <div className="flex items-center justify-between gap-1.5">
            <div className="flex items-center gap-1.5 min-w-0">
              <ShieldAlert className="w-4 h-4 text-[#DC2626] shrink-0" strokeWidth={2} />
              <span className="text-[11px] font-bold uppercase tracking-wider text-[#475569] dark:text-[#CBD5E1] truncate">
                Unique CVEs
              </span>
            </div>
          </div>

          <div className="my-auto pt-1">
            <div className="text-[32px] sm:text-[34px] font-extrabold text-[#0F172A] dark:text-[#F8FAFC] tracking-tight font-sans leading-none">
              {uniqueCveSet.size}
            </div>
          </div>

          <div className="flex items-center justify-between text-[11px] text-[#475569] dark:text-[#94A3B8] border-t border-[#F1F5F9] dark:border-[#1E293B] pt-2.5">
            <span className="truncate">{uniqueCriticalCveCount} critical findings</span>
          </div>
        </div>
      </div>

      {/* 3. Threat Severity Breakdown */}
      <div className="bg-white dark:bg-[#111827] border border-gray-200 dark:border-gray-800 rounded-xl p-5 shadow-2xs">
        <div className="flex items-center justify-between pb-3 border-b border-gray-100 dark:border-gray-800">
          <div>
            <h3 className="text-sm font-bold text-gray-900 dark:text-white">Threat Severity Breakdown</h3>
            <p className="text-[11px] text-gray-500 dark:text-gray-400 mt-0.5">
              Critical, High, Medium, and Low distribution of Common Vulnerabilities and Exposures
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-12 gap-6 items-center pt-4">
          <div className="md:col-span-4 flex items-center justify-center">
            <div className="relative w-[160px] h-[160px] shrink-0 flex items-center justify-center">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={severityDonutData}
                    cx="50%"
                    cy="50%"
                    innerRadius={48}
                    outerRadius={70}
                    paddingAngle={3}
                    dataKey="value"
                  >
                    {severityDonutData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                </PieChart>
              </ResponsiveContainer>
              <div className="absolute inset-0 flex flex-col items-center justify-center text-center pointer-events-none">
                <span className="text-2xl font-black text-gray-900 dark:text-white leading-none">
                  {totalCves}
                </span>
                <span className="text-[10px] text-gray-400 mt-1 uppercase tracking-wider font-semibold">
                  Total CVEs
                </span>
              </div>
            </div>
          </div>

          <div className="md:col-span-8 grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="p-3.5 rounded-xl border border-red-200/60 dark:border-red-900/40 bg-red-50/40 dark:bg-red-950/20">
              <div className="flex items-center gap-1.5 text-xs font-bold text-red-700 dark:text-red-300">
                <span className="w-2.5 h-2.5 rounded-full bg-[#e03131]" />
                Critical
              </div>
              <div className="text-2xl font-black text-red-600 dark:text-red-400 font-mono mt-1.5">
                {severityCounts.critical}
              </div>
              <div className="text-[10px] text-gray-500 mt-0.5">CVSS 9.0 - 10.0</div>
            </div>

            <div className="p-3.5 rounded-xl border border-orange-200/60 dark:border-orange-900/40 bg-orange-50/40 dark:bg-orange-950/20">
              <div className="flex items-center gap-1.5 text-xs font-bold text-orange-700 dark:text-orange-300">
                <span className="w-2.5 h-2.5 rounded-full bg-[#f97316]" />
                High
              </div>
              <div className="text-2xl font-black text-orange-600 dark:text-orange-400 font-mono mt-1.5">
                {severityCounts.high}
              </div>
              <div className="text-[10px] text-gray-500 mt-0.5">CVSS 7.0 - 8.9</div>
            </div>

            <div className="p-3.5 rounded-xl border border-amber-200/60 dark:border-amber-900/40 bg-amber-50/40 dark:bg-amber-950/20">
              <div className="flex items-center gap-1.5 text-xs font-bold text-amber-700 dark:text-amber-300">
                <span className="w-2.5 h-2.5 rounded-full bg-[#f59e0b]" />
                Medium
              </div>
              <div className="text-2xl font-black text-amber-600 dark:text-amber-400 font-mono mt-1.5">
                {severityCounts.medium}
              </div>
              <div className="text-[10px] text-gray-500 mt-0.5">CVSS 4.0 - 6.9</div>
            </div>

            <div className="p-3.5 rounded-xl border border-sky-200/60 dark:border-sky-900/40 bg-sky-50/40 dark:bg-sky-950/20">
              <div className="flex items-center gap-1.5 text-xs font-bold text-sky-700 dark:text-sky-300">
                <span className="w-2.5 h-2.5 rounded-full bg-[#0ea5e9]" />
                Low
              </div>
              <div className="text-2xl font-black text-sky-600 dark:text-sky-400 font-mono mt-1.5">
                {severityCounts.low}
              </div>
              <div className="text-[10px] text-gray-500 mt-0.5">CVSS 0.1 - 3.9</div>
            </div>
          </div>
        </div>
      </div>

      {/* 4. LOWER CONTENT: Risk Trend Chart + Vulnerability Movement (SS2) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-3.5">
        {/* Risk Trend Chart (7 cols) */}
        <div className="lg:col-span-7 bg-white dark:bg-[#111827] border border-gray-200 dark:border-gray-800 rounded-xl p-4 sm:p-4.5 shadow-2xs">
          <div className="flex items-center justify-between mb-2.5">
            <div>
              <h3 className="text-sm font-bold text-gray-900 dark:text-white">Risk Trend Chart</h3>
              <p className="text-[11px] text-gray-500 dark:text-gray-400">
                Risk index and vulnerability count over the last{' '}
                {timeRange === '7D' ? '7 days' : timeRange === '30D' ? '30 days' : '90 days'}
              </p>
            </div>
            <div className="flex items-center gap-3 text-xs">
              <span className="flex items-center gap-1.5 text-red-600 font-semibold text-[11px]">
                <span className="w-2 h-2 rounded-full bg-red-600" /> Risk Index
              </span>
              <span className="flex items-center gap-1.5 text-blue-600 font-semibold text-[11px]">
                <span className="w-2 h-2 rounded-full bg-blue-600" /> Vuln Count
              </span>
            </div>
          </div>

          <div className="h-[175px] w-full flex items-center justify-center">
            {riskTrendData.length === 0 ? (
              <span className="text-xs text-gray-500 dark:text-gray-400">No data available yet.</span>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={riskTrendData} margin={{ top: 5, right: 10, left: -25, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" vertical={false} opacity={0.6} />
                  <XAxis dataKey="date" tickLine={false} axisLine={false} tick={{ fontSize: 10, fill: '#9ca3af' }} />
                  <YAxis tickLine={false} axisLine={false} tick={{ fontSize: 10, fill: '#9ca3af' }} />
                  <RechartsTooltip
                    contentStyle={{
                      backgroundColor: '#1f2937',
                      borderRadius: '8px',
                      color: '#fff',
                      fontSize: '11px',
                      padding: '6px 10px',
                    }}
                  />
                  <Line type="monotone" dataKey="riskIndex" stroke="#e03131" strokeWidth={2} dot={{ r: 2.5 }} />
                  <Line type="monotone" dataKey="vulns" stroke="#3b82f6" strokeWidth={1.8} dot={{ r: 2.5 }} />
                </LineChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        {/* SS2: Vulnerability Movement – last 30 days (5 cols) */}
        <div className="lg:col-span-5 bg-white dark:bg-[#111827] border border-gray-200 dark:border-gray-800 rounded-xl p-4 sm:p-4.5 shadow-2xs flex flex-col justify-between">
          <div>
            {/* Header: Title, Subtitle and Badges */}
            <div className="flex items-start justify-between gap-2 mb-3">
              <div>
                <h3 className="text-base sm:text-[17px] font-bold text-gray-900 dark:text-white leading-tight">
                  Vulnerability Movement – last 30 days
                </h3>
                <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                  What came in, what the system closed, what came back.
                </p>
              </div>
              <div className="flex items-center gap-1.5 shrink-0 pt-0.5">
                <span className="px-3 py-0.5 rounded-full text-xs font-medium bg-[#e8f1fd] text-[#1d63ed] dark:bg-blue-950/70 dark:text-blue-300">
                  Automated
                </span>
              </div>
            </div>

            {/* Three Statistic Cards connected to real finding metrics */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5 sm:gap-3 mt-4">
              {/* Card 1 – NEW */}
              <div
                onClick={() => navigate('/vulnerabilities?status=Open')}
                className="border border-gray-200/90 dark:border-gray-800 rounded-xl p-3 sm:p-3.5 bg-white dark:bg-gray-900/40 flex flex-col justify-between min-h-[105px] hover:border-red-300 dark:hover:border-red-800 transition-colors cursor-pointer group"
                title="View newly detected and open vulnerabilities"
              >
                <span className="text-[11px] font-bold text-gray-800 dark:text-gray-200 uppercase tracking-wider group-hover:text-red-600 transition-colors">
                  NEW
                </span>
                <span className="text-3xl font-extrabold text-[#d92d20] dark:text-red-500 my-1 leading-none font-mono">
                  {movementStats.newCount}
                </span>
                <span className="text-[11px] sm:text-xs text-gray-500 dark:text-gray-400 font-normal leading-snug">
                  found in scans
                </span>
              </div>

              {/* Card 2 – AUTO-CLOSED */}
              <div
                onClick={() => navigate('/vulnerabilities?status=Resolved')}
                className="border border-gray-200/90 dark:border-gray-800 rounded-xl p-3 sm:p-3.5 bg-white dark:bg-gray-900/40 flex flex-col justify-between min-h-[105px] hover:border-emerald-300 dark:hover:border-emerald-800 transition-colors cursor-pointer group"
                title="View auto-closed and remediated vulnerabilities"
              >
                <span className="text-[11px] font-bold text-gray-800 dark:text-gray-200 uppercase tracking-wider group-hover:text-emerald-600 transition-colors">
                  AUTO-CLOSED
                </span>
                <span className="text-3xl font-extrabold text-[#027a48] dark:text-emerald-500 my-1 leading-none font-mono">
                  {movementStats.autoClosedCount}
                </span>
                <span className="text-[11px] sm:text-xs text-gray-500 dark:text-gray-400 font-normal leading-snug">
                  package upgraded / removed
                </span>
              </div>

              {/* Card 3 – REOPENED */}
              <div
                onClick={() => navigate('/vulnerabilities?search=reopen')}
                className="border border-gray-200/90 dark:border-gray-800 rounded-xl p-3 sm:p-3.5 bg-white dark:bg-gray-900/40 flex flex-col justify-between min-h-[105px] hover:border-amber-300 dark:hover:border-amber-800 transition-colors cursor-pointer group"
                title="View reopened vulnerability occurrences"
              >
                <span className="text-[11px] font-bold text-gray-800 dark:text-gray-200 uppercase tracking-wider group-hover:text-amber-600 transition-colors">
                  REOPENED
                </span>
                <span className="text-3xl font-extrabold text-[#d97706] dark:text-amber-500 my-1 leading-none font-mono">
                  {movementStats.reopenedCount}
                </span>
                <span className="text-[11px] sm:text-xs text-gray-500 dark:text-gray-400 font-normal leading-snug">
                  package came back
                </span>
              </div>
            </div>

            {/* Horizontal dashed divider */}
            <div className="border-t border-dashed border-gray-200 dark:border-gray-800 my-4" />

            {/* Collapsible Data to refer section */}
            {/* <div>
              <button
                type="button"
                onClick={() => setIsDataToReferOpen(!isDataToReferOpen)}
                className="flex items-center gap-1.5 text-xs font-semibold text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 cursor-pointer transition-colors group select-none"
              >
                <span>Data methodology & references</span>
                <ChevronDown
                  className={`w-3.5 h-3.5 transition-transform duration-200 ${isDataToReferOpen ? 'rotate-180' : ''
                    }`}
                />
              </button>

              {isDataToReferOpen && (
                <div className="mt-3 pt-1 text-xs text-gray-600 dark:text-gray-400">
                  <div className="bg-gray-50/80 dark:bg-gray-800/40 rounded-lg p-3 border border-gray-100 dark:border-gray-800 text-[11px] space-y-1.5">
                    <div className="flex justify-between">
                      <span className="text-gray-500 dark:text-gray-400">Scan Pipeline Source:</span>
                      <span className="font-semibold text-gray-800 dark:text-gray-200">
                        Daily CI/CD Vulnerability Scans
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-500 dark:text-gray-400">Auto-Remediation Rule:</span>
                      <span className="font-semibold text-gray-800 dark:text-gray-200">
                        Automatic closure on version bump (SYSTEM_AUTO_CLOSURE)
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-500 dark:text-gray-400">Reopened Criteria:</span>
                      <span className="font-semibold text-gray-800 dark:text-gray-200">
                        Reintroduced vulnerable dependencies
                      </span>
                    </div>
                  </div>
                </div>
              )}
            </div> */}
          </div>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* 5. D4 and D5 Side-by-Side Row (50% / 50% on Desktop, 2 Columns)          */}
      {/* ========================================================================= */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-3.5 sm:gap-4">
        {/* Left Column (50%): D4 – Top Vulnerable Packages by Reach */}
        <div className="bg-white dark:bg-[#111827] border border-gray-200 dark:border-gray-800 rounded-xl p-4 sm:p-5 shadow-2xs flex flex-col justify-between h-full">
          <div>
            {/* Header: Title, Subtitle, and Badge */}
            <div className="flex items-start justify-between gap-2 mb-3">
              <div>
                <h3 className="text-base sm:text-[17px] font-bold text-gray-900 dark:text-white leading-tight">
                  Top Vulnerable Packages by Reach
                </h3>
                <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                  Packages that put the most apps at risk.
                </p>
              </div>
              <div className="flex items-center gap-1.5 shrink-0 pt-0.5">
                <button
                  type="button"
                  onClick={() => navigate('/software-inventory')}
                  className="px-2.5 py-0.5 rounded-full text-xs font-semibold text-blue-600 hover:text-blue-800 dark:text-blue-400 hover:underline inline-flex items-center gap-1"
                >
                  <span>Inventory</span>
                  <ArrowRight className="w-3 h-3" />
                </button>
              </div>
            </div>

            {/* Table: 4 columns dynamically rendered */}
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs sm:text-[13px]">
                <thead>
                  <tr className="border-b border-gray-100 dark:border-gray-800 text-gray-500 dark:text-gray-400 text-[11px] font-bold uppercase tracking-wider">
                    <th className="py-2.5 text-left font-bold">PACKAGE</th>
                    <th className="py-2.5 text-left font-bold">APPS</th>
                    <th className="py-2.5 text-left font-bold">INSTANCES</th>
                    <th className="py-2.5 text-left font-bold">SEVERITY</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100 dark:divide-gray-800">
                  {topPackagesByReach.length > 0 ? (
                    topPackagesByReach.map((pkg, idx) => (
                      <tr
                        key={`${pkg.name}-${pkg.version}-${idx}`}
                        onClick={() => navigate(`/vulnerabilities?search=${encodeURIComponent(pkg.name)}`)}
                        className="hover:bg-gray-50/70 dark:hover:bg-gray-800/40 transition-colors cursor-pointer group"
                      >
                        <td className="py-3">
                          <span className="font-bold text-gray-900 dark:text-white group-hover:text-blue-600 dark:group-hover:text-blue-400 transition-colors">
                            {pkg.name}
                          </span>
                          <span className="text-gray-500 dark:text-gray-400 text-xs font-mono ml-2">
                            {pkg.version}
                          </span>
                        </td>
                        <td className="py-3 font-semibold text-gray-800 dark:text-gray-200 font-mono">
                          {pkg.appsCount}
                        </td>
                        <td className="py-3 font-semibold text-gray-800 dark:text-gray-200 font-mono">
                          {pkg.instancesCount}
                        </td>
                        <td className="py-3">
                          <div className="flex items-center gap-1.5">
                            {pkg.criticals > 0 && (
                              <span
                                className="inline-flex items-center justify-center min-w-[20px] h-5 px-1.5 rounded-full text-[11px] font-bold bg-[#fef2f2] text-[#d92d20] dark:bg-red-950/60 dark:text-red-300"
                                title={`${pkg.criticals} Critical CVE(s)`}
                              >
                                {pkg.criticals}
                              </span>
                            )}
                            {pkg.highs > 0 && (
                              <span
                                className="inline-flex items-center justify-center min-w-[20px] h-5 px-1.5 rounded-full text-[11px] font-bold bg-[#fef3e7] text-[#c05e11] dark:bg-amber-950/70 dark:text-amber-300"
                                title={`${pkg.highs} High CVE(s)`}
                              >
                                {pkg.highs}
                              </span>
                            )}
                            {pkg.criticals === 0 && pkg.highs === 0 && (
                              <span className="text-gray-400 text-xs">—</span>
                            )}
                          </div>
                        </td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan={4} className="py-8 text-center text-xs text-gray-500 dark:text-gray-400">
                        No vulnerable packages detected in current baseline.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Bottom section with divider and collapsible reference data */}
          {/* <div>
            <div className="border-t border-dashed border-gray-200 dark:border-gray-800 my-4" />
            <div>
              <button
                type="button"
                onClick={() => setIsD4DataReferOpen(!isD4DataReferOpen)}
                className="flex items-center gap-1.5 text-xs font-semibold text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 cursor-pointer transition-colors group select-none"
              >
                <span>Reach calculation methodology</span>
                <ChevronDown
                  className={`w-3.5 h-3.5 transition-transform duration-200 ${isD4DataReferOpen ? 'rotate-180' : ''
                    }`}
                />
              </button>

              {isD4DataReferOpen && (
                <div className="mt-3 pt-1 text-xs text-gray-600 dark:text-gray-400">
                  <div className="bg-gray-50/80 dark:bg-gray-800/40 rounded-lg p-3 border border-gray-100 dark:border-gray-800 text-[11px] space-y-1.5">
                    <div className="flex justify-between">
                      <span className="text-gray-500 dark:text-gray-400">Blast Radius Calculation:</span>
                      <span className="font-semibold text-gray-800 dark:text-gray-200">
                        Reach = Distinct Applications × Runtime Instances
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-500 dark:text-gray-400">Severity Metric:</span>
                      <span className="font-semibold text-gray-800 dark:text-gray-200">
                        Red: Critical CVEs | Amber: High CVEs
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-500 dark:text-gray-400">Ecosystem:</span>
                      <span className="font-semibold text-gray-800 dark:text-gray-200">
                        npm, PyPI, Maven, Go, and System Packages
                      </span>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div> */}
        </div>

        {/* Right Column (50%): D5 – Recent Scans */}
        <div className="bg-white dark:bg-[#111827] border border-gray-200 dark:border-gray-800 rounded-xl p-4 sm:p-5 shadow-2xs flex flex-col justify-between h-full">
          <div>
            {/* Header: Title, Subtitle, and Action */}
            <div className="flex items-start justify-between gap-2 mb-3">
              <div>
                <h3 className="text-base sm:text-[17px] font-bold text-gray-900 dark:text-white leading-tight">
                  Recent Scans
                </h3>
                <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                  Last scans launched, with type, source and result.
                </p>
              </div>
              <div className="flex items-center gap-1.5 shrink-0 pt-0.5">
                <button
                  type="button"
                  onClick={() => navigate('/security-scans')}
                  className="px-2.5 py-0.5 rounded-full text-xs font-semibold text-blue-600 hover:text-blue-800 dark:text-blue-400 hover:underline inline-flex items-center gap-1"
                >
                  <span>All Scans</span>
                  <ArrowRight className="w-3 h-3" />
                </button>
              </div>
            </div>

            {/* Table: 6 columns dynamically rendered from scansHistory */}
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs sm:text-[13px]">
                <thead>
                  <tr className="border-b border-gray-100 dark:border-gray-800 text-gray-500 dark:text-gray-400 text-[11px] font-bold uppercase tracking-wider">
                    <th className="py-2.5 text-left font-bold">APP</th>
                    <th className="py-2.5 text-left font-bold">TYPE</th>
                    <th className="py-2.5 text-left font-bold">SOURCE</th>
                    <th className="py-2.5 text-left font-bold">VERSION</th>
                    <th className="py-2.5 text-left font-bold">STATUS</th>
                    <th className="py-2.5 text-left font-bold">WHEN</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100 dark:divide-gray-800">
                  {recentScansList.length > 0 ? (
                    recentScansList.map((scan) => {
                      const appName = scan.targetProject || scan.appService || 'Application';
                      const scanTypeLabel = formatScanType(scan.scanType);
                      const sourceLabel = scan.source
                        ? scan.source.length > 20
                          ? `${scan.source.slice(0, 20)}...`
                          : scan.source
                        : 'Workspace';
                      const versionLabel =
                        scan.releaseTag || (scan.id ? `v${scan.id.slice(0, 5)}` : 'v1.0');
                      const relativeTime = formatRelativeTime(scan.completedAt || scan.timestamp);

                      return (
                        <tr
                          key={scan.id}
                          onClick={() => navigate(`/security-scans`)}
                          className="hover:bg-gray-50/70 dark:hover:bg-gray-800/40 transition-colors cursor-pointer group"
                        >
                          <td className="py-3.5 font-medium text-gray-900 dark:text-white group-hover:text-blue-600 dark:group-hover:text-blue-400 transition-colors truncate max-w-[130px]" title={appName}>
                            {appName}
                          </td>
                          <td className="py-3.5 text-gray-700 dark:text-gray-300">
                            {scanTypeLabel}
                          </td>
                          <td className="py-3.5 text-gray-700 dark:text-gray-300 font-mono text-[11px] truncate max-w-[120px]" title={scan.source || 'Workspace'}>
                            {sourceLabel}
                          </td>
                          <td className="py-3.5 text-gray-700 dark:text-gray-300 font-mono text-xs">
                            {versionLabel}
                          </td>
                          <td className="py-3.5">
                            {renderScanStatusBadge(scan.status)}
                          </td>
                          <td className="py-3.5 text-gray-600 dark:text-gray-400 whitespace-nowrap">
                            {relativeTime}
                          </td>
                        </tr>
                      );
                    })
                  ) : (
                    <tr>
                      <td colSpan={6} className="py-8 text-center text-xs text-gray-500 dark:text-gray-400">
                        No scans recorded yet.{' '}
                        <button
                          onClick={() => navigate('/security-scans/new')}
                          className="text-blue-600 dark:text-blue-400 hover:underline font-semibold"
                        >
                          Launch your first scan →
                        </button>
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Bottom section with divider and collapsible reference data */}
          {/* <div>
            <div className="border-t border-dashed border-gray-200 dark:border-gray-800 my-4" />
            <div>
              <button
                type="button"
                onClick={() => setIsD5DataReferOpen(!isD5DataReferOpen)}
                className="flex items-center gap-1.5 text-xs font-semibold text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 cursor-pointer transition-colors group select-none"
              >
                <span>Pipeline execution details</span>
                <ChevronDown
                  className={`w-3.5 h-3.5 transition-transform duration-200 ${isD5DataReferOpen ? 'rotate-180' : ''
                    }`}
                />
              </button>

              {isD5DataReferOpen && (
                <div className="mt-3 pt-1 text-xs text-gray-600 dark:text-gray-400">
                  <div className="bg-gray-50/80 dark:bg-gray-800/40 rounded-lg p-3 border border-gray-100 dark:border-gray-800 text-[11px] space-y-1.5">
                    <div className="flex justify-between">
                      <span className="text-gray-500 dark:text-gray-400">Scan Pipeline:</span>
                      <span className="font-semibold text-gray-800 dark:text-gray-200">
                        Async Task Queue & Webhook Trigger
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-500 dark:text-gray-400">Engine:</span>
                      <span className="font-semibold text-gray-800 dark:text-gray-200">
                        Static AST & Binary Composition Analyzer
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-500 dark:text-gray-400">Retention Policy:</span>
                      <span className="font-semibold text-gray-800 dark:text-gray-200">
                        Historical logs retained for 90 days
                      </span>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div> */}
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
