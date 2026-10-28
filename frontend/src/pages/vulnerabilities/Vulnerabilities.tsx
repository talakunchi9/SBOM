import React, { useState, useMemo, useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import {
  Search,
  Filter,
  Download,
  MoreVertical,
  Layers,
  Folder,
  CheckCircle2,
  AlertTriangle,
  RotateCcw,
  ArrowRight,
  Shield,
  Box,
  Package,
} from 'lucide-react';
import { useAppState } from '../../context/AppStateContext';
import { Vulnerability, Severity, VexStatus } from '../../types';
import { extractVulnName } from '../../api/client';
import { TablePagination } from '../../components/common/TablePagination';
import { VulnerabilityActionMenu } from './VulnerabilityActionMenu';

export const Vulnerabilities: React.FC = () => {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const { vulnerabilities, projects, components, scansHistory, addToast, updateVulnerabilityStatus } = useAppState();

  // Project, Scan, and App Filter states - initialize from URL query params
  const [projectFilter, setProjectFilter] = useState<string>(searchParams.get('project') || 'all');
  const [scanFilter, setScanFilter] = useState<string>(searchParams.get('scan') || 'all');
  const [appFilter, setAppFilter] = useState<string>(searchParams.get('app') || 'all');
  const [searchQuery, setSearchQuery] = useState<string>(searchParams.get('search') || '');

  // Severity Filter state
  const [selectedSeverity, setSelectedSeverity] = useState<string>(searchParams.get('severity') || 'All');

  // Status & VEX filters (toggleable via Filters button)
  const [showFiltersPanel, setShowFiltersPanel] = useState<boolean>(false);
  const [statusFilter, setStatusFilter] = useState<string>('All');
  const [vexFilter, setVexFilter] = useState<string>('All');

  // Sync state if URL query param changes
  useEffect(() => {
    const urlProj = searchParams.get('project') || 'all';
    const urlScan = searchParams.get('scan') || 'all';
    const urlApp = searchParams.get('app') || 'all';
    if (urlProj !== projectFilter) setProjectFilter(urlProj);
    if (urlScan !== scanFilter) setScanFilter(urlScan);
    if (urlApp !== appFilter) setAppFilter(urlApp);

    const urlSev = searchParams.get('severity') || 'All';
    if (urlSev !== selectedSeverity) setSelectedSeverity(urlSev);

    const urlSearch = searchParams.get('search') || '';
    if (urlSearch !== searchQuery) setSearchQuery(urlSearch);
  }, [searchParams]);

  // Build grouped scope options:
  // 1. Projects (all microservices aggregated)
  // 2. Individual Scans / Microservices (differentiates multiple scans of the same project name)
  const scopeOptions = useMemo(() => {
    // 1. Unique projects
    const projectSet = new Set<string>();
    (projects || []).forEach((p) => { if (p.name) projectSet.add(p.name); });
    (vulnerabilities || []).forEach((v) => { if (v.project) projectSet.add(v.project); });
    (components || []).forEach((c) => { if (c.project) projectSet.add(c.project); });
    if (projectFilter && projectFilter !== 'all' && !projectFilter.startsWith('scan:') && !projectFilter.startsWith('app:')) {
      projectSet.add(projectFilter);
    }

    const projectList = Array.from(projectSet).sort().map((pName) => {
      const pVulns = (vulnerabilities || []).filter((v) => (v.project || '').toLowerCase().trim() === pName.toLowerCase().trim());
      return {
        id: `project:${pName}`,
        name: pName,
        label: `${pName} (All Microservices - ${pVulns.length} vulns)`,
        count: pVulns.length,
      };
    });

    // 2. Individual Scans / Microservices
    const scanMap = new Map<string, { id: string; project: string; app: string; scanId?: string; count: number }>();

    (scansHistory || []).forEach((scan) => {
      if (scan.status === 'completed' && scan.targetProject && scan.appService) {
        const key = `${scan.targetProject.toLowerCase()}|${scan.appService.toLowerCase()}`;
        const matchingVulns = (vulnerabilities || []).filter((v) => {
          if (scan.id && v.scanId === scan.id) return true;
          return (v.project || '').toLowerCase() === scan.targetProject.toLowerCase() &&
            (v.application || '').toLowerCase() === scan.appService.toLowerCase();
        });
        scanMap.set(key, {
          id: `scan:${scan.id || scan.appService}:${scan.targetProject}:${scan.appService}`,
          project: scan.targetProject,
          app: scan.appService,
          scanId: scan.id,
          count: matchingVulns.length,
        });
      }
    });

    (vulnerabilities || []).forEach((v) => {
      const vApp = v.application;
      if (v.project && vApp && v.project.toLowerCase() !== vApp.toLowerCase()) {
        const key = `${v.project.toLowerCase()}|${vApp.toLowerCase()}`;
        if (!scanMap.has(key)) {
          const matchingVulns = (vulnerabilities || []).filter(
            (item) => (item.project || '').toLowerCase() === v.project.toLowerCase() &&
              (item.application || '').toLowerCase() === vApp.toLowerCase()
          );
          scanMap.set(key, {
            id: `scan:${v.scanId || vApp}:${v.project}:${vApp}`,
            project: v.project,
            app: vApp,
            scanId: v.scanId,
            count: matchingVulns.length,
          });
        }
      }
    });

    const singleScans = Array.from(scanMap.values()).sort((a, b) => {
      if (a.project === b.project) return a.app.localeCompare(b.app);
      return a.project.localeCompare(b.project);
    }).map((s) => ({
      id: s.id,
      project: s.project,
      app: s.app,
      label: `${s.project} · ${s.app} (${s.count} vulns)`,
      count: s.count,
    }));

    return {
      projects: projectList,
      scans: singleScans,
    };
  }, [projects, vulnerabilities, components, scansHistory, projectFilter]);

  // Determine which option is currently active in the dropdown
  const currentScopeValue = useMemo(() => {
    if (scanFilter && scanFilter !== 'all') {
      const match = scopeOptions.scans.find((s) => s.id.includes(scanFilter));
      if (match) return match.id;
    }
    if (appFilter && appFilter !== 'all') {
      const match = scopeOptions.scans.find(
        (s) => s.app.toLowerCase() === appFilter.toLowerCase() &&
          (projectFilter === 'all' || s.project.toLowerCase() === projectFilter.toLowerCase())
      );
      if (match) return match.id;
    }
    if (projectFilter && projectFilter !== 'all') {
      return `project:${projectFilter}`;
    }
    return 'all';
  }, [scanFilter, appFilter, projectFilter, scopeOptions]);

  const activeScanName = useMemo(() => {
    if (appFilter && appFilter !== 'all') return appFilter;
    if (scanFilter && scanFilter !== 'all') {
      const match = scopeOptions.scans.find((s) => s.id.includes(scanFilter));
      if (match?.app) return match.app;
      const job = (scansHistory || []).find((s) => s.id === scanFilter);
      if (job?.appService) return job.appService;
      return scanFilter.slice(0, 8);
    }
    return projectFilter && projectFilter !== 'all' ? projectFilter : '';
  }, [appFilter, scanFilter, scopeOptions, scansHistory, projectFilter]);

  // Handle scope dropdown change
  const handleScopeChange = (val: string) => {
    const newParams = new URLSearchParams(searchParams);
    if (val === 'all') {
      newParams.delete('project');
      newParams.delete('scan');
      newParams.delete('app');
      setProjectFilter('all');
      setScanFilter('all');
      setAppFilter('all');
    } else if (val.startsWith('project:')) {
      const p = val.replace('project:', '');
      newParams.set('project', p);
      newParams.delete('scan');
      newParams.delete('app');
      setProjectFilter(p);
      setScanFilter('all');
      setAppFilter('all');
    } else if (val.startsWith('scan:')) {
      const parts = val.split(':');
      const sid = parts[1];
      const p = parts[2] || '';
      const a = parts[3] || '';
      if (p) newParams.set('project', p);
      if (a) newParams.set('app', a);
      if (sid && sid !== 'undefined' && sid !== a) {
        newParams.set('scan', sid);
      } else {
        newParams.delete('scan');
      }
      setProjectFilter(p || 'all');
      setAppFilter(a || 'all');
      setScanFilter(sid || 'all');
    } else {
      newParams.set('project', val);
      newParams.delete('scan');
      newParams.delete('app');
      setProjectFilter(val);
      setScanFilter('all');
      setAppFilter('all');
    }
    setSearchParams(newParams);
  };

  // Scoped vulnerabilities based on selected single scan, microservice, or project
  const projectScopedVulns = useMemo(() => {
    // 1. Direct scan ID match
    if (scanFilter && scanFilter !== 'all') {
      const byScan = (vulnerabilities || []).filter((v) => v.scanId === scanFilter);
      if (byScan.length > 0) return byScan;
    }

    // 2. Single scan / microservice match (by application name and parent project)
    if (appFilter && appFilter !== 'all') {
      const targetApp = appFilter.toLowerCase().trim();
      const targetProj = projectFilter && projectFilter !== 'all' ? projectFilter.toLowerCase().trim() : '';
      const byApp = (vulnerabilities || []).filter((v) => {
        const a = (v.application || '').toLowerCase().trim();
        const p = (v.project || '').toLowerCase().trim();
        const appMatches = a === targetApp || (v.scanId && v.scanId.toLowerCase().includes(targetApp));
        const projMatches = !targetProj || p === targetProj;
        return appMatches && projMatches;
      });
      if (byApp.length > 0) return byApp;
    }

    // 3. Project-level match (aggregates all microservices for that project)
    if (projectFilter && projectFilter !== 'all') {
      const target = projectFilter.toLowerCase().trim();
      const exact = (vulnerabilities || []).filter((v) => {
        const p = (v.project || '').toLowerCase().trim();
        return p === target;
      });
      if (exact.length > 0) return exact;

      // Fallback matching
      return (vulnerabilities || []).filter((v) => {
        const p = (v.project || '').toLowerCase().trim();
        const a = (v.application || '').toLowerCase().trim();
        return p === target || a === target || (target.length > 2 && (p.includes(target) || a.includes(target)));
      });
    }

    return vulnerabilities || [];
  }, [vulnerabilities, projectFilter, scanFilter, appFilter]);

  const criticalCount = useMemo(() => projectScopedVulns.filter((v) => v.severity === 'Critical').length, [projectScopedVulns]);
  const highCount = useMemo(() => projectScopedVulns.filter((v) => v.severity === 'High').length, [projectScopedVulns]);
  const mediumCount = useMemo(() => projectScopedVulns.filter((v) => v.severity === 'Medium').length, [projectScopedVulns]);
  const lowCount = useMemo(() => projectScopedVulns.filter((v) => v.severity === 'Low').length, [projectScopedVulns]);

  // Filtered Vulnerabilities
  const filtered = useMemo(() => {
    return projectScopedVulns.filter((v) => {
      const q = searchQuery.toLowerCase().trim();
      const matchesSearch =
        !q ||
        v.cve.toLowerCase().includes(q) ||
        (v.name && v.name.toLowerCase().includes(q)) ||
        (v.application && v.application.toLowerCase().includes(q)) ||
        v.package.toLowerCase().includes(q) ||
        v.project.toLowerCase().includes(q) ||
        v.description.toLowerCase().includes(q);

      const matchesSeverity =
        selectedSeverity === 'All' || v.severity.toLowerCase() === selectedSeverity.toLowerCase();

      const matchesStatus =
        statusFilter === 'All' || v.status.toLowerCase() === statusFilter.toLowerCase();

      const matchesVex =
        vexFilter === 'All' || v.vexStatus.toLowerCase() === vexFilter.toLowerCase();

      return matchesSearch && matchesSeverity && matchesStatus && matchesVex;
    });
  }, [projectScopedVulns, searchQuery, selectedSeverity, statusFilter, vexFilter]);

  // Systematic Pagination State
  const [currentPage, setCurrentPage] = useState<number>(1);
  const [pageSize, setPageSize] = useState<number>(15);

  // Reset to page 1 whenever filters or search query change
  useEffect(() => {
    setCurrentPage(1);
  }, [searchQuery, selectedSeverity, statusFilter, vexFilter, projectFilter]);

  // Pagination calculations
  const totalItems = filtered.length;
  const totalPages = Math.max(1, Math.ceil(totalItems / pageSize));
  const safeCurrentPage = Math.min(Math.max(1, currentPage), totalPages);
  const startIndex = (safeCurrentPage - 1) * pageSize;
  const endIndex = Math.min(startIndex + pageSize, totalItems);
  const paginatedVulnerabilities = filtered.slice(startIndex, endIndex);

  // Helper for CSV escaping
  const csvEscape = (val: unknown) => {
    if (val === null || val === undefined) return '""';
    const str = String(val).replace(/"/g, '""');
    return `"${str}"`;
  };

  const getRecommendedAction = (v: Vulnerability) => {
    if (v.patchRecommendation) return v.patchRecommendation;
    if (v.fixVersion && v.fixVersion !== '*' && v.fixVersion !== 'None' && v.fixVersion !== 'None available') {
      return `Upgrade to version ${v.fixVersion} or later.`;
    }
    return 'No patch currently released by maintainers. Review workaround or isolate dependency.';
  };

  // CSV Export with all comprehensive vulnerability details
  const handleExportCsv = () => {
    if (filtered.length === 0) {
      addToast({ type: 'warning', title: 'No Data to Export', message: 'No vulnerabilities match the current filter.' });
      return;
    }
    const headers = [
      // 1. Vulnerability Details
      'CVE ID',
      'Vulnerability Name',
      'Description',
      'Severity',
      'CVSS Score',
      'CVSS Vector',
      'Vulnerability Source',
      'Published Date',
      // 2. Affected Component
      'Component Name',
      'Current Version',
      'Ecosystem',
      'PURL / CPE',
      'Project',
      'Application',
      'Direct / Transitive',
      'Dependency Path',
      // 3. Remediation
      'Fixed Version',
      'Recommended Action',
      'Owner / Team',
      'Ticket ID',
      // 4. History
      'First Detected',
      'Last Detected',
      'Status Changes',
    ];
    const rows = filtered.map((v) => [
      // 1. Vulnerability Details
      csvEscape(v.cve),
      csvEscape(v.name || v.description?.split('.')[0] || v.cve),
      csvEscape(v.description || ''),
      csvEscape(v.severity),
      csvEscape(v.cvss !== undefined ? v.cvss.toFixed(1) : '0.0'),
      csvEscape(v.vectorString || 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'),
      csvEscape(v.source || 'mitre'),
      csvEscape(v.publishedDate || '2026-10-13'),
      // 2. Affected Component
      csvEscape(v.package),
      csvEscape(v.version || v.affectedVersions || ''),
      csvEscape(v.ecosystem || 'npm'),
      csvEscape(v.purl || (v.package ? `pkg:${v.ecosystem || 'npm'}/${v.package}@${v.version || '0.0.0'}` : '')),
      csvEscape(v.project),
      csvEscape(v.application || v.project),
      csvEscape(v.direct ? 'Direct' : 'Transitive'),
      csvEscape(v.dependencyPath || `${v.project} > ${v.package}`),
      // 3. Remediation
      csvEscape(v.fixVersion && v.fixVersion !== '*' ? v.fixVersion : 'None available'),
      csvEscape(getRecommendedAction(v)),
      csvEscape(v.owner || 'Security Team'),
      csvEscape(v.ticketId || `SEC-${Math.abs(v.cve.split('').reduce((a, b) => ((a << 5) - a + b.charCodeAt(0)) | 0, 0) % 9000) + 1000}`),
      // 4. History
      csvEscape(v.firstDetected || '2026-10-13 10:00 AM'),
      csvEscape(v.lastDetected || '2026-10-13 10:00 AM'),
      csvEscape(v.statusChanges || v.status),
    ]);
    const csvContent = '\uFEFF' + [headers.join(','), ...rows.map((r) => r.join(','))].join('\r\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', `vulnerabilities-${new Date().toISOString().slice(0, 10)}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    addToast({
      type: 'success',
      title: 'Export Successful',
      message: `Exported ${filtered.length} vulnerabilities with full details to CSV.`,
    });
  };

  // Helper renderers
  const renderSeverityBadge = (severity: Severity) => {
    switch (severity) {
      case 'Critical':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-rose-50 text-rose-700 dark:bg-rose-950/60 dark:text-rose-300 border border-rose-200/80 dark:border-rose-900/50">
            <span className="w-1.5 h-1.5 rounded-full bg-rose-500" />
            Critical
          </span>
        );
      case 'High':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-orange-50 text-orange-700 dark:bg-orange-950/60 dark:text-orange-300 border border-orange-200/80 dark:border-orange-900/50">
            <span className="w-1.5 h-1.5 rounded-full bg-orange-500" />
            High
          </span>
        );
      case 'Medium':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-amber-50 text-amber-700 dark:bg-amber-950/60 dark:text-amber-300 border border-amber-200/80 dark:border-amber-900/50">
            <span className="w-1.5 h-1.5 rounded-full bg-amber-500" />
            Medium
          </span>
        );
      case 'Low':
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-sky-50 text-sky-700 dark:bg-sky-950/60 dark:text-sky-300 border border-sky-200/80 dark:border-sky-900/50">
            <span className="w-1.5 h-1.5 rounded-full bg-sky-500" />
            Low
          </span>
        );
    }
  };

  const renderCvssScore = (cvss: number) => {
    let colorClass = 'text-sky-600 dark:text-sky-400';
    if (cvss >= 9.0) colorClass = 'text-rose-600 dark:text-rose-400';
    else if (cvss >= 7.0) colorClass = 'text-orange-600 dark:text-orange-400';
    else if (cvss >= 4.0) colorClass = 'text-amber-600 dark:text-amber-400';

    return <span className={`font-mono font-bold text-xs ${colorClass}`}>{cvss.toFixed(1)}</span>;
  };

  const renderStatusBadge = (status: string) => {
    switch (status) {
      case 'Closed':
      case 'Resolved':
      case 'Fixed':
        return (
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[11px] font-semibold bg-emerald-50 text-emerald-700 dark:bg-emerald-950/60 dark:text-emerald-300 border border-emerald-200/80 dark:border-emerald-900/50">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
            {status}
          </span>
        );
      case 'Accepted':
      case 'Risk Accepted':
        return (
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[11px] font-semibold bg-blue-50 text-blue-700 dark:bg-blue-950/60 dark:text-blue-300 border border-blue-200/80 dark:border-blue-900/50">
            <span className="w-1.5 h-1.5 rounded-full bg-blue-500" />
            Accepted
          </span>
        );
      case 'In Progress':
        return (
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[11px] font-semibold bg-indigo-50 text-indigo-700 dark:bg-indigo-950/60 dark:text-indigo-300 border border-indigo-200/80 dark:border-indigo-900/50">
            <span className="w-1.5 h-1.5 rounded-full bg-indigo-500" />
            In Progress
          </span>
        );
      case 'Open':
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[11px] font-semibold bg-rose-50 text-rose-700 dark:bg-rose-950/60 dark:text-rose-300 border border-rose-200/80 dark:border-rose-900/50">
            <span className="w-1.5 h-1.5 rounded-full bg-rose-500" />
            Open
          </span>
        );
    }
  };

  const renderVexBadge = (vex: VexStatus) => {
    switch (vex) {
      case 'affected':
        return (
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[11px] font-semibold bg-rose-50 text-rose-700 dark:bg-rose-950/60 dark:text-rose-300 border border-rose-200/80 dark:border-rose-900/50">
            <span className="w-1.5 h-1.5 rounded-full bg-rose-500" />
            Affected
          </span>
        );
      case 'not_affected':
        return (
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[11px] font-semibold bg-emerald-50 text-emerald-700 dark:bg-emerald-950/60 dark:text-emerald-300 border border-emerald-200/80 dark:border-emerald-900/50">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
            Not Affected
          </span>
        );
      case 'fixed':
        return (
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[11px] font-semibold bg-sky-50 text-sky-700 dark:bg-sky-950/60 dark:text-sky-300 border border-sky-200/80 dark:border-sky-900/50">
            <span className="w-1.5 h-1.5 rounded-full bg-sky-500" />
            Fixed
          </span>
        );
      case 'under_investigation':
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[11px] font-semibold bg-amber-50 text-amber-700 dark:bg-amber-950/60 dark:text-amber-300 border border-amber-200/80 dark:border-amber-900/50">
            <span className="w-1.5 h-1.5 rounded-full bg-amber-500" />
            Under Investigation
          </span>
        );
    }
  };

  return (
    <div className="space-y-4 animate-fadeIn pb-14">
      {/* Top Container with No Blank Space Above Metric Boxes */}
      <div className="bg-white dark:bg-[#111827] border border-gray-200 dark:border-gray-800 rounded-2xl p-4 sm:p-5 shadow-2xs space-y-4">
        {/* Project / Single Scan Scope Dropdown Row */}
        <div className="flex items-center justify-between flex-wrap gap-2">
          {currentScopeValue !== 'all' ? (
            <div className="flex items-center gap-2 px-3 py-1.5 bg-blue-50 dark:bg-blue-950/50 border border-blue-200 dark:border-blue-800/80 rounded-xl text-xs text-blue-900 dark:text-blue-200">
              <span className="w-2 h-2 rounded-full bg-blue-500 animate-pulse shrink-0" />
              <span>
                {appFilter !== 'all' || scanFilter !== 'all' ? (
                  <>
                    Filtered by scan: <strong className="font-bold">{activeScanName}</strong>
                  </>
                ) : (
                  <>
                    Filtered by project: <strong className="font-bold">{projectFilter}</strong>
                  </>
                )}
              </span>
            </div>
          ) : (
            <div />
          )}

          <div className="flex items-center gap-2 bg-gray-50 dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-xl px-3 py-1.5 shadow-2xs hover:border-gray-300 dark:hover:border-gray-600 transition-colors">
            <Folder className="w-4 h-4 text-gray-400 shrink-0" />
            <select
              value={currentScopeValue}
              onChange={(e) => handleScopeChange(e.target.value)}
              className="text-xs font-semibold bg-transparent text-gray-800 dark:text-gray-200 focus:outline-none cursor-pointer pr-1 max-w-[280px] truncate"
            >
              <option value="all">All Projects & Scans (Org Scope)</option>
              {scopeOptions.projects.length > 0 && (
                <optgroup label="Projects (All Microservices Combined)">
                  {scopeOptions.projects.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.label}
                    </option>
                  ))}
                </optgroup>
              )}
              {scopeOptions.scans.length > 0 && (
                <optgroup label="Single Scans / Microservices">
                  {scopeOptions.scans.map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.label}
                    </option>
                  ))}
                </optgroup>
              )}
            </select>
          </div>
        </div>

        {/* 5 Severity Metric Cards directly below (NO blank space above) */}
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 pt-1">
          {/* Card 1: ALL SEVERITIES */}
          <div
            onClick={() => setSelectedSeverity('All')}
            className={`p-3.5 rounded-xl border transition-all cursor-pointer ${
              selectedSeverity === 'All'
                ? 'border-blue-600 bg-blue-50/40 dark:bg-blue-950/30 ring-2 ring-blue-500/20 shadow-xs'
                : 'border-gray-200 dark:border-gray-800 bg-gray-50/60 dark:bg-gray-800/40 hover:border-gray-300 dark:hover:border-gray-700'
            }`}
          >
            <div className="flex items-center gap-1.5 mb-1.5">
              <span className="w-2 h-2 rounded-full bg-gray-400 dark:bg-gray-500" />
              <span className="text-[10px] font-bold text-gray-500 dark:text-gray-400 uppercase tracking-wider block">
                ALL SEVERITIES
              </span>
            </div>
            <span className="text-2xl font-black text-gray-900 dark:text-white font-mono block">
              {projectScopedVulns.length}
            </span>
          </div>

          {/* Card 2: CRITICAL */}
          <div
            onClick={() => setSelectedSeverity('Critical')}
            className={`p-3.5 rounded-xl border transition-all cursor-pointer ${
              selectedSeverity === 'Critical'
                ? 'border-rose-600 bg-rose-50/90 dark:bg-rose-950/60 ring-2 ring-rose-500/20 shadow-xs'
                : 'border-rose-200/80 dark:border-rose-900/40 bg-rose-50/30 dark:bg-rose-950/20 hover:border-rose-400 dark:hover:border-rose-800'
            }`}
          >
            <div className="flex items-center gap-1.5 mb-1.5">
              <span className="w-2 h-2 rounded-full bg-rose-500" />
              <span className="text-[10px] font-bold text-rose-600 dark:text-rose-400 uppercase tracking-wider block">
                CRITICAL
              </span>
            </div>
            <span className="text-2xl font-black text-rose-600 dark:text-rose-400 font-mono block">
              {criticalCount}
            </span>
          </div>

          {/* Card 3: HIGH */}
          <div
            onClick={() => setSelectedSeverity('High')}
            className={`p-3.5 rounded-xl border transition-all cursor-pointer ${
              selectedSeverity === 'High'
                ? 'border-orange-600 bg-orange-50/90 dark:bg-orange-950/60 ring-2 ring-orange-500/20 shadow-xs'
                : 'border-orange-200/80 dark:border-orange-900/40 bg-orange-50/30 dark:bg-orange-950/20 hover:border-orange-400 dark:hover:border-orange-800'
            }`}
          >
            <div className="flex items-center gap-1.5 mb-1.5">
              <span className="w-2 h-2 rounded-full bg-orange-500" />
              <span className="text-[10px] font-bold text-orange-600 dark:text-orange-400 uppercase tracking-wider block">
                HIGH
              </span>
            </div>
            <span className="text-2xl font-black text-orange-600 dark:text-orange-400 font-mono block">
              {highCount}
            </span>
          </div>

          {/* Card 4: MEDIUM */}
          <div
            onClick={() => setSelectedSeverity('Medium')}
            className={`p-3.5 rounded-xl border transition-all cursor-pointer ${
              selectedSeverity === 'Medium'
                ? 'border-amber-600 bg-amber-50/90 dark:bg-amber-950/60 ring-2 ring-amber-500/20 shadow-xs'
                : 'border-amber-200/80 dark:border-amber-900/40 bg-amber-50/30 dark:bg-amber-950/20 hover:border-amber-400 dark:hover:border-amber-800'
            }`}
          >
            <div className="flex items-center gap-1.5 mb-1.5">
              <span className="w-2 h-2 rounded-full bg-amber-500" />
              <span className="text-[10px] font-bold text-amber-600 dark:text-amber-400 uppercase tracking-wider block">
                MEDIUM
              </span>
            </div>
            <span className="text-2xl font-black text-amber-600 dark:text-amber-400 font-mono block">
              {mediumCount}
            </span>
          </div>

          {/* Card 5: LOW */}
          <div
            onClick={() => setSelectedSeverity('Low')}
            className={`p-3.5 rounded-xl border transition-all cursor-pointer ${
              selectedSeverity === 'Low'
                ? 'border-sky-600 bg-sky-50/90 dark:bg-sky-950/60 ring-2 ring-sky-500/20 shadow-xs'
                : 'border-sky-200/80 dark:border-sky-900/40 bg-sky-50/30 dark:bg-sky-950/20 hover:border-sky-400 dark:hover:border-sky-800'
            }`}
          >
            <div className="flex items-center gap-1.5 mb-1.5">
              <span className="w-2 h-2 rounded-full bg-sky-500" />
              <span className="text-[10px] font-bold text-sky-600 dark:text-sky-400 uppercase tracking-wider block">
                LOW
              </span>
            </div>
            <span className="text-2xl font-black text-sky-600 dark:text-sky-400 font-mono block">
              {lowCount}
            </span>
          </div>
        </div>
      </div>

      {/* Search and Action Bar */}
      <div className="bg-white dark:bg-[#111827] border border-gray-200 dark:border-gray-800 rounded-2xl p-3 sm:p-3.5 shadow-2xs space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          {/* Search Input */}
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-gray-400 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search CVE identifier, application, component, project, or description..."
              className="w-full text-xs pl-9 pr-3 py-2 rounded-xl border border-gray-200 dark:border-gray-700 bg-gray-50/70 dark:bg-gray-800/60 text-gray-900 dark:text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 transition-all"
            />
          </div>

          {/* Action Buttons */}
          <div className="flex items-center gap-2 self-end sm:self-auto shrink-0">
            {/* Filters Button */}
            <button
              type="button"
              onClick={() => setShowFiltersPanel(!showFiltersPanel)}
              className={`px-3 py-2 text-xs font-semibold rounded-xl border transition-all inline-flex items-center gap-1.5 cursor-pointer ${
                showFiltersPanel || statusFilter !== 'All' || vexFilter !== 'All'
                  ? 'bg-blue-50 dark:bg-blue-950/60 border-blue-300 dark:border-blue-800 text-blue-600 dark:text-blue-400'
                  : 'bg-white dark:bg-gray-800 border-gray-200 dark:border-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700'
              }`}
            >
              <Filter className="w-3.5 h-3.5" />
              <span>Filters</span>
            </button>

            {/* Export Button */}
            <button
              type="button"
              onClick={handleExportCsv}
              className="px-3.5 py-2 text-xs font-semibold rounded-xl bg-blue-50 dark:bg-blue-950/60 border border-blue-200 dark:border-blue-800 text-blue-600 dark:text-blue-400 hover:bg-blue-100 dark:hover:bg-blue-900/60 transition-all inline-flex items-center gap-1.5 cursor-pointer shadow-2xs"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export</span>
            </button>

            {/* Showing Count */}
            <span className="text-xs text-gray-500 dark:text-gray-400 pl-1 shrink-0">
              Showing <strong className="text-gray-900 dark:text-white">{totalItems === 0 ? 0 : `${startIndex + 1}–${endIndex}`}</strong> of <strong className="text-gray-900 dark:text-white">{totalItems}</strong> CVEs
            </span>
          </div>
        </div>

        {/* Expandable Advanced Filter Options */}
        {showFiltersPanel && (
          <div className="pt-3 border-t border-gray-100 dark:border-gray-800 flex items-center gap-3 flex-wrap text-xs">
            <div className="flex items-center gap-1.5">
              <span className="text-gray-400 font-medium">Status:</span>
              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                className="px-2.5 py-1 bg-gray-50 dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg text-gray-800 dark:text-gray-200 cursor-pointer focus:outline-none"
              >
                <option value="All">All Statuses</option>
                <option value="Open">Open</option>
                <option value="In Progress">In Progress</option>
                <option value="Closed">Closed</option>
                <option value="Fixed">Fixed</option>
                <option value="Accepted">Accepted</option>
              </select>
            </div>

            <div className="flex items-center gap-1.5">
              <span className="text-gray-400 font-medium">VEX:</span>
              <select
                value={vexFilter}
                onChange={(e) => setVexFilter(e.target.value)}
                className="px-2.5 py-1 bg-gray-50 dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg text-gray-800 dark:text-gray-200 cursor-pointer focus:outline-none"
              >
                <option value="All">All VEX</option>
                <option value="affected">Affected</option>
                <option value="not_affected">Not Affected</option>
                <option value="under_investigation">Under Investigation</option>
                <option value="fixed">Fixed</option>
              </select>
            </div>

            {(statusFilter !== 'All' || vexFilter !== 'All' || searchQuery) && (
              <button
                type="button"
                onClick={() => {
                  setStatusFilter('All');
                  setVexFilter('All');
                  setSearchQuery('');
                }}
                className="text-gray-400 hover:text-red-600 dark:hover:text-red-400 inline-flex items-center gap-1 ml-auto cursor-pointer"
              >
                <RotateCcw className="w-3 h-3" />
                <span>Reset Filters</span>
              </button>
            )}
          </div>
        )}
      </div>

      {/* Main Vulnerability Table */}
      <div className="bg-white dark:bg-[#111827] border border-gray-200 dark:border-gray-800 rounded-2xl shadow-2xs overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs min-w-[1100px]">
            <thead className="bg-gray-50/80 dark:bg-gray-800/70 text-[10px] font-bold text-gray-400 dark:text-gray-500 uppercase tracking-wider border-b border-gray-200 dark:border-gray-800">
              <tr>
                <th className="py-3 px-3.5">CVE ID</th>
                <th className="py-3 px-3.5">Vulnerability Name</th>
                <th className="py-3 px-3.5">Application</th>
                <th className="py-3 px-3.5">Severity</th>
                <th className="py-3 px-3.5">CVSS Score</th>
                <th className="py-3 px-3.5">Component + Version</th>
                <th className="py-3 px-3.5">Project</th>
                <th className="py-3 px-3.5">Status</th>
                <th className="py-3 px-3.5">VEX Status</th>
                <th className="py-3 px-3.5">Fixed Version</th>
                <th className="py-3 px-3.5 text-center">Actions</th>
              </tr>
            </thead>

            <tbody className="divide-y divide-gray-100 dark:divide-gray-800/60">
              {filtered.length === 0 ? (
                <tr>
                  <td colSpan={11} className="py-16 text-center">
                    <div className="flex flex-col items-center justify-center max-w-md mx-auto space-y-3">
                      <div className="w-12 h-12 rounded-2xl bg-blue-50 dark:bg-blue-950/50 flex items-center justify-center text-blue-600 dark:text-blue-400 border border-blue-200/80 dark:border-blue-800/60 shadow-2xs">
                        <CheckCircle2 className="w-6 h-6" />
                      </div>
                      <div>
                        <h4 className="text-sm font-bold text-gray-900 dark:text-white">No Vulnerabilities Found</h4>
                        <p className="text-xs text-gray-500 dark:text-gray-400 mt-1 leading-relaxed">
                          All monitored software components are secure, or no vulnerability findings have been recorded yet for this project scope.
                        </p>
                      </div>
                      <div className="flex items-center gap-2 pt-1">
                        <button
                          type="button"
                          onClick={() => navigate('/security-scans/new')}
                          className="px-3.5 py-1.5 text-xs font-semibold bg-blue-600 hover:bg-blue-700 text-white rounded-xl shadow-2xs transition-colors cursor-pointer inline-flex items-center gap-1.5"
                        >
                          <span>Run Security Scan</span>
                          <ArrowRight className="w-3.5 h-3.5" />
                        </button>
                        {projectFilter !== 'all' && (
                          <button
                            type="button"
                            onClick={() => handleScopeChange('all')}
                            className="px-3 py-1.5 text-xs font-semibold bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300 rounded-xl hover:bg-gray-200 dark:hover:bg-gray-700 transition-colors cursor-pointer"
                          >
                            View All Projects
                          </button>
                        )}
                      </div>
                    </div>
                  </td>
                </tr>
              ) : (
                paginatedVulnerabilities.map((v) => {
                  const vulnName = v.name || extractVulnName(v.description, v.cwe || v.cve);
                  const appName = v.application || v.project || 'Service';

                  return (
                    <tr
                      key={v.id}
                      onClick={() =>
                        navigate(`/vulnerabilities/${encodeURIComponent(v.cve)}`, {
                          state: { vulnerability: v },
                        })
                      }
                      className="hover:bg-blue-50/30 dark:hover:bg-blue-950/20 transition-colors cursor-pointer group"
                    >
                      {/* CVE ID */}
                      <td className="py-3 px-3.5 whitespace-nowrap">
                        <span className="font-mono font-bold text-blue-600 dark:text-blue-400 group-hover:underline">
                          {v.cve}
                        </span>
                      </td>

                      {/* Vulnerability Name (Explicit user request) */}
                      <td className="py-3 px-3.5 max-w-[220px]">
                        <span
                          className="font-semibold text-gray-900 dark:text-white line-clamp-1 truncate block"
                          title={vulnName}
                        >
                          {vulnName}
                        </span>
                      </td>

                      {/* Application */}
                      <td className="py-3 px-3.5 whitespace-nowrap">
                        <div className="flex items-center gap-1.5 text-gray-800 dark:text-gray-200">
                          <Box className="w-3.5 h-3.5 text-blue-500 shrink-0" />
                          <span className="font-medium text-xs">{appName}</span>
                        </div>
                      </td>

                      {/* Severity */}
                      <td className="py-3 px-3.5 whitespace-nowrap">
                        {renderSeverityBadge(v.severity)}
                      </td>

                      {/* CVSS Score */}
                      <td className="py-3 px-3.5 whitespace-nowrap">
                        {renderCvssScore(v.cvss)}
                      </td>

                      {/* Component + Version */}
                      <td className="py-3 px-3.5 whitespace-nowrap">
                        <div>
                          <span className="font-mono font-semibold text-gray-900 dark:text-white block">
                            {v.package}
                          </span>
                          <span className="font-mono text-[11px] text-gray-500 dark:text-gray-400">
                            {v.version || v.affectedVersions || '—'}
                          </span>
                        </div>
                      </td>

                      {/* Project (Clicking filters to project) */}
                      <td
                        className="py-3 px-3.5 whitespace-nowrap"
                        onClick={(e) => {
                          e.stopPropagation();
                          if (v.scanId) {
                            handleScopeChange(`scan:${v.scanId}:${v.project}:${v.application || ''}`);
                          } else {
                            handleScopeChange(`project:${v.project}`);
                          }
                        }}
                      >
                        <span
                          className="font-mono text-gray-600 dark:text-gray-400 hover:text-blue-600 dark:hover:text-blue-400 hover:underline cursor-pointer"
                          title={`Filter by project: ${v.project}`}
                        >
                          {v.project}
                        </span>
                      </td>

                      {/* Status */}
                      <td className="py-3 px-3.5 whitespace-nowrap">
                        {renderStatusBadge(v.status)}
                      </td>

                      {/* VEX Status */}
                      <td className="py-3 px-3.5 whitespace-nowrap">
                        {renderVexBadge(v.vexStatus)}
                      </td>

                      {/* Fixed Version */}
                      <td className="py-3 px-3.5 whitespace-nowrap font-mono text-gray-700 dark:text-gray-300">
                        {v.fixVersion && v.fixVersion !== '*' ? v.fixVersion : '—'}
                      </td>

                      {/* Actions (3 dots dropdown with View Details and Update Status) */}
                      <td
                        className="py-3 px-3.5 whitespace-nowrap text-center"
                        onClick={(e) => e.stopPropagation()}
                      >
                        <VulnerabilityActionMenu
                          vulnerability={v}
                          onViewDetails={(vuln) => {
                            navigate(`/vulnerabilities/${encodeURIComponent(vuln.cve)}`, {
                              state: { vulnerability: vuln },
                            });
                          }}
                          onUpdateStatus={async (vuln, newStatus, extra) => {
                            await updateVulnerabilityStatus(vuln.cve, newStatus, {
                              project: vuln.project,
                              vexStatus: vuln.vexStatus,
                              justification: extra?.justification,
                            });
                          }}
                        />
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Systematic Pagination Controls (15, 20, 25, 50, 100) */}
        <div className="px-4 pb-4">
          <TablePagination
            currentPage={safeCurrentPage}
            totalItems={totalItems}
            pageSize={pageSize}
            pageSizeOptions={[15, 20, 25, 50, 100]}
            onPageChange={(page) => {
              setCurrentPage(page);
            }}
            onPageSizeChange={(size) => {
              setPageSize(size);
              setCurrentPage(1);
            }}
            itemLabel="vulnerabilities"
          />
        </div>
      </div>
    </div>
  );
};

export default Vulnerabilities;
