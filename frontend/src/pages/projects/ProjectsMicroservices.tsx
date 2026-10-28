import React, { useEffect, useMemo, useState } from 'react';
import { NavLink, useNavigate, useSearchParams, useLocation } from 'react-router-dom';
import {
  FolderGit2,
  Package,
  FileCode,
  ShieldCheck,
  Scan,
  Search,
  ChevronRight,
  Eye,
  ExternalLink,
  X,
  Layers,
  AlertTriangle,
} from 'lucide-react';
import { ApiError, listProjects, type ApiProjectRow, type ApiProjectSummary } from '../../api/client';
import { useAppState } from '../../context/AppStateContext';
import { TablePagination } from '../../components/common/TablePagination';

const EMPTY_SUMMARY: ApiProjectSummary = {
  project_count: 0,
  active_projects: 0,
  avg_compliance_pct: 0,
  compliant_count: 0,
  total_count: 0,
  total_scans: 0,
  sbom_files: 0,
};

function riskColor(risk: ApiProjectRow['risk']): string {
  if (risk === 'High Risk') return 'bg-red-50 text-red-700 border-red-200 dark:bg-red-950/40 dark:text-red-300 dark:border-red-900/50';
  if (risk === 'Needs Attention') return 'bg-amber-50 text-amber-700 border-amber-200 dark:bg-amber-950/40 dark:text-amber-300 dark:border-amber-900/50';
  return 'bg-emerald-50 text-emerald-700 border-emerald-200 dark:bg-emerald-950/40 dark:text-emerald-300 dark:border-emerald-900/50';
}

function relativeTime(iso: string): string {
  if (!iso) return '—';
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return iso;
  const seconds = Math.max(0, Math.round((Date.now() - then) / 1000));
  if (seconds < 45) return 'Just now';
  if (seconds < 3600) return `${Math.max(1, Math.round(seconds / 60))}m ago`;
  if (seconds < 86400) return `${Math.max(1, Math.round(seconds / 3600))}h ago`;
  if (seconds < 604800) return `${Math.max(1, Math.round(seconds / 86400))}d ago`;
  return new Date(iso).toLocaleDateString();
}

export const ProjectsMicroservices: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const [searchParams, setSearchParams] = useSearchParams();
  const { addToast, components, vulnerabilities, scansHistory } = useAppState();
  const tabSearch = location.search;
  const [searchQuery, setSearchQuery] = useState(searchParams.get('q') || '');
  const [statusFilter, setStatusFilter] = useState(searchParams.get('status') || 'All Statuses');
  const [summary, setSummary] = useState<ApiProjectSummary>(EMPTY_SUMMARY);
  const [projectsList, setProjectsList] = useState<ApiProjectRow[]>([]);
  const [selectedProjectModal, setSelectedProjectModal] = useState<ApiProjectRow | null>(null);
  const [loading, setLoading] = useState(true);
  const toastOnce = React.useRef(false);

  // Pagination state (Systematic 15, 20, 25, 50, 100 per page)
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(15);

  useEffect(() => {
    setCurrentPage(1);
  }, [searchQuery, statusFilter, pageSize]);

  const totalItems = projectsList.length;
  const totalPages = Math.max(1, Math.ceil(totalItems / pageSize));
  const safeCurrentPage = Math.min(Math.max(1, currentPage), totalPages);
  const startIndex = (safeCurrentPage - 1) * pageSize;
  const endIndex = Math.min(startIndex + pageSize, totalItems);
  const paginatedProjects = projectsList.slice(startIndex, endIndex);

  useEffect(() => {
    let cancelled = false;
    const timer = window.setTimeout(async () => {
      setLoading(true);
      try {
        const data = await listProjects({
          q: searchQuery.trim() || undefined,
          status: statusFilter,
        });
        if (cancelled) return;
        setSummary(data.summary || EMPTY_SUMMARY);
        setProjectsList(data.projects || []);
        toastOnce.current = false;
      } catch (err) {
        if (cancelled) return;
        setSummary(EMPTY_SUMMARY);
        setProjectsList([]);
        // Avoid toast storms when addToast identity changes after each notification.
        if (!toastOnce.current) {
          toastOnce.current = true;
          addToast({
            type: 'error',
            title: 'Projects unavailable',
            message: err instanceof ApiError ? err.message : 'Could not load projects from scans.',
          });
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    }, 200);
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [searchQuery, statusFilter, addToast]);

  const emptyMessage = useMemo(() => {
    if (loading) return 'Loading projects discovered from scans…';
    if (searchQuery || statusFilter !== 'All Statuses') {
      return 'No projects match the current search or status filter.';
    }
    return 'No projects or microservices available yet. Real services will appear once discovered from scans.';
  }, [loading, searchQuery, statusFilter]);

  return (
    <div className="space-y-5 animate-fadeIn pb-16">
      <div className="border-b border-gray-200 dark:border-gray-800">
        <nav className="flex items-center space-x-2 sm:space-x-3 overflow-x-auto" aria-label="Software Inventory Tabs">
          <NavLink
            to={`/software-inventory${tabSearch}`}
            end
            className={({ isActive }) =>
              `flex items-center gap-2 py-2.5 px-3.5 text-xs font-semibold rounded-t-lg transition-all cursor-pointer whitespace-nowrap shrink-0 border-b-2 ${
                isActive
                  ? 'bg-blue-50/80 dark:bg-blue-950/40 text-blue-600 dark:text-blue-400 border-blue-600 font-bold shadow-2xs'
                  : 'border-transparent text-gray-500 hover:text-gray-800 dark:text-gray-400 dark:hover:text-gray-200 hover:bg-gray-50 dark:hover:bg-gray-800/40'
              }`
            }
          >
            <Package className="w-4 h-4" />
            <span>Software Components & Packages</span>
          </NavLink>

          <NavLink
            to={`/software-inventory/projects${tabSearch}`}
            className={({ isActive }) =>
              `flex items-center gap-2 py-2.5 px-3.5 text-xs font-semibold rounded-t-lg transition-all cursor-pointer whitespace-nowrap shrink-0 border-b-2 ${
                isActive
                  ? 'bg-blue-50/80 dark:bg-blue-950/40 text-blue-600 dark:text-blue-400 border-blue-600 font-bold shadow-2xs'
                  : 'border-transparent text-gray-500 hover:text-gray-800 dark:text-gray-400 dark:hover:text-gray-200 hover:bg-gray-50 dark:hover:bg-gray-800/40'
              }`
            }
          >
            <FolderGit2 className="w-4 h-4 text-blue-600 dark:text-blue-400" />
            <span>Projects & Microservices</span>
          </NavLink>

          <NavLink
            to={`/software-inventory/artifacts${tabSearch}`}
            className={({ isActive }) =>
              `flex items-center gap-2 py-2.5 px-3.5 text-xs font-semibold rounded-t-lg transition-all cursor-pointer whitespace-nowrap shrink-0 border-b-2 ${
                isActive
                  ? 'bg-blue-50/80 dark:bg-blue-950/40 text-blue-600 dark:text-blue-400 border-blue-600 font-bold shadow-2xs'
                  : 'border-transparent text-gray-500 hover:text-gray-800 dark:text-gray-400 dark:hover:text-gray-200 hover:bg-gray-50 dark:hover:bg-gray-800/40'
              }`
            }
          >
            <FileCode className="w-4 h-4" />
            <span>SBOM Documents & Artifacts</span>
          </NavLink>
        </nav>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
        <div className="bg-white dark:bg-[#111827] border border-gray-200 dark:border-gray-800 rounded-xl p-4 shadow-2xs flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <div className="w-8 h-8 rounded-lg bg-blue-50 dark:bg-blue-950/60 text-blue-600 flex items-center justify-center">
                <FolderGit2 className="w-4 h-4" />
              </div>
              <span className="text-[11px] font-bold uppercase tracking-wider text-gray-500 dark:text-gray-400">
                PROJECTS
              </span>
            </div>
            <ChevronRight className="w-4 h-4 text-gray-400" />
          </div>
          <div className="mt-3">
            <h2 className="text-2xl font-bold text-gray-900 dark:text-white">{summary.project_count}</h2>
            <p className="text-[11px] text-gray-400 mt-0.5">{summary.active_projects} active projects</p>
          </div>
        </div>

        <div className="bg-white dark:bg-[#111827] border border-gray-200 dark:border-gray-800 rounded-xl p-4 shadow-2xs flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <div className="w-8 h-8 rounded-lg bg-emerald-50 dark:bg-emerald-950/60 text-emerald-600 flex items-center justify-center">
                <ShieldCheck className="w-4 h-4" />
              </div>
              <span className="text-[11px] font-bold uppercase tracking-wider text-gray-500 dark:text-gray-400">
                AVG COMPLIANCE
              </span>
            </div>
            <ChevronRight className="w-4 h-4 text-gray-400" />
          </div>
          <div className="mt-3">
            <h2 className="text-2xl font-bold text-gray-900 dark:text-white">{summary.avg_compliance_pct.toFixed(1)}%</h2>
            <p className="text-[11px] text-gray-400 mt-0.5">
              {summary.compliant_count} / {summary.total_count} compliant
            </p>
          </div>
        </div>

        <div className="bg-white dark:bg-[#111827] border border-gray-200 dark:border-gray-800 rounded-xl p-4 shadow-2xs flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <div className="w-8 h-8 rounded-lg bg-blue-50 dark:bg-blue-950/60 text-blue-600 flex items-center justify-center">
                <Scan className="w-4 h-4" />
              </div>
              <span className="text-[11px] font-bold uppercase tracking-wider text-gray-500 dark:text-gray-400">
                TOTAL SCANS
              </span>
            </div>
            <ChevronRight className="w-4 h-4 text-gray-400" />
          </div>
          <div className="mt-3">
            <h2 className="text-2xl font-bold text-gray-900 dark:text-white">{summary.total_scans}</h2>
            <p className="text-[11px] text-gray-400 mt-0.5">{summary.total_scans} total scans</p>
          </div>
        </div>

        <div className="bg-white dark:bg-[#111827] border border-gray-200 dark:border-gray-800 rounded-xl p-4 shadow-2xs flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <div className="w-8 h-8 rounded-lg bg-orange-50 dark:bg-orange-950/60 text-orange-600 flex items-center justify-center">
                <FileCode className="w-4 h-4" />
              </div>
              <span className="text-[11px] font-bold uppercase tracking-wider text-gray-500 dark:text-gray-400">
                SBOM FILES
              </span>
            </div>
            <ChevronRight className="w-4 h-4 text-gray-400" />
          </div>
          <div className="mt-3">
            <h2 className="text-2xl font-bold text-gray-900 dark:text-white">{summary.sbom_files}</h2>
            <p className="text-[11px] text-gray-400 mt-0.5">{summary.sbom_files} files generated</p>
          </div>
        </div>
      </div>

      <div className="bg-white dark:bg-[#111827] border border-gray-200 dark:border-gray-800 rounded-xl p-5 shadow-2xs space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 pb-3 border-b border-gray-100 dark:border-gray-800">
          <div>
            <h3 className="text-sm font-bold text-gray-900 dark:text-white">SBOM Projects</h3>
            <p className="text-xs text-gray-500 dark:text-gray-400 mt-0.5">
              Risk + compliance mapped per project from completed scans
            </p>
          </div>

          <div className="flex items-center gap-2 flex-wrap">
            <div className="relative">
              <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-gray-400 pointer-events-none" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => {
                  const next = e.target.value;
                  setSearchQuery(next);
                  const params = new URLSearchParams(searchParams);
                  if (next.trim()) params.set('q', next.trim());
                  else params.delete('q');
                  setSearchParams(params, { replace: true });
                }}
                placeholder="Search projects"
                className="pl-9 pr-3 py-1.5 text-xs bg-gray-50 dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg text-gray-900 dark:text-white focus:outline-none focus:ring-1 focus:ring-blue-500"
              />
            </div>

            <select
              value={statusFilter}
              onChange={(e) => {
                const next = e.target.value;
                setStatusFilter(next);
                const params = new URLSearchParams(searchParams);
                if (next && next !== 'All Statuses') params.set('status', next);
                else params.delete('status');
                setSearchParams(params, { replace: true });
              }}
              className="text-xs px-3 py-1.5 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg text-gray-700 dark:text-gray-300 cursor-pointer focus:outline-none"
            >
              <option value="All Statuses">All Statuses</option>
              <option value="High Risk">High Risk</option>
              <option value="Needs Attention">Needs Attention</option>
              <option value="Healthy">Healthy</option>
            </select>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs min-w-[850px]">
            <thead>
              <tr className="text-gray-500 dark:text-gray-400 border-b border-gray-100 dark:border-gray-800">
                <th className="pb-3 pr-4 font-semibold whitespace-nowrap">NAME</th>
                <th className="pb-3 px-4 font-semibold whitespace-nowrap">CLASSIFIER</th>
                <th className="pb-3 px-4 font-semibold whitespace-nowrap">AVG RISK LEVEL</th>
                <th className="pb-3 px-4 font-semibold whitespace-nowrap">COMPLIANCE</th>
                <th className="pb-3 px-4 font-semibold whitespace-nowrap">COMPONENTS</th>
                <th className="pb-3 px-4 font-semibold whitespace-nowrap">VULNS</th>
                <th className="pb-3 px-4 font-semibold whitespace-nowrap">TAGS</th>
                <th className="pb-3 px-4 font-semibold whitespace-nowrap">HISTORY</th>
                <th className="pb-3 pl-4 font-semibold whitespace-nowrap text-right">ACTIONS</th>
              </tr>
            </thead>
            {projectsList.length > 0 ? (
              <tbody className="divide-y divide-gray-100 dark:divide-gray-800">
                {paginatedProjects.map((p) => {
                  const projectComps = (components || []).filter((c) => (c.project || '').toLowerCase().trim() === p.name.toLowerCase().trim());
                  const compCount = p.component_count || (projectComps.length > 0 ? projectComps.length : p.scans);
                  const projectVulns = (vulnerabilities || []).filter((v) => (v.project || '').toLowerCase().trim() === p.name.toLowerCase().trim());
                  const vulnCount = p.vulns > 0 ? p.vulns : projectVulns.length;

                  return (
                    <tr key={p.id} className="hover:bg-gray-50/70 dark:hover:bg-gray-800/40 transition-colors">
                      <td
                        onClick={() => setSelectedProjectModal(p)}
                        className="py-3.5 pr-4 font-bold text-blue-600 dark:text-blue-400 whitespace-nowrap cursor-pointer hover:underline hover:text-blue-700 dark:hover:text-blue-300 transition-colors"
                        title={`Click to view details for ${p.name}`}
                      >
                        {p.name}
                      </td>
                      <td className="py-3.5 px-4 text-gray-600 dark:text-gray-400 whitespace-nowrap">{p.classifier}</td>
                      <td className="py-3.5 px-4 whitespace-nowrap">
                        <span className={`px-2.5 py-0.5 rounded text-[10px] font-bold border ${riskColor(p.risk)}`}>
                          {p.risk}
                        </span>
                      </td>
                      <td className="py-3.5 px-4 font-semibold text-gray-900 dark:text-white whitespace-nowrap">{p.compliance}</td>
                      <td
                        onClick={() => navigate(`/software-inventory?project=${encodeURIComponent(p.name)}`)}
                        className="py-3.5 px-4 font-semibold text-blue-600 dark:text-blue-400 whitespace-nowrap cursor-pointer hover:underline"
                        title={`View ${compCount} components in Software Inventory for ${p.name}`}
                      >
                        <span className="font-mono">{compCount}</span>
                      </td>
                      <td
                        onClick={() => navigate(`/vulnerabilities?project=${encodeURIComponent(p.name)}`)}
                        className="py-3.5 px-4 font-semibold whitespace-nowrap cursor-pointer hover:underline"
                        title={`View ${vulnCount} findings in Vulnerability Management for ${p.name}`}
                      >
                        {vulnCount > 0 ? (
                          <span className="text-red-600 dark:text-red-400 font-bold font-mono">{vulnCount}</span>
                        ) : (
                          <span className="text-gray-400 font-mono">0</span>
                        )}
                      </td>
                      <td className="py-3.5 px-4">
                        <div className="flex gap-1 flex-wrap">
                          {p.tags.map((t) => (
                            <span
                              key={t}
                              className="px-1.5 py-0.5 bg-gray-100 dark:bg-gray-800 text-[10px] rounded text-gray-600 dark:text-gray-400 whitespace-nowrap"
                            >
                              {t}
                            </span>
                          ))}
                        </div>
                      </td>
                      <td className="py-3.5 px-4 text-gray-500 dark:text-gray-400 whitespace-nowrap">
                        {relativeTime(p.last_scanned_at)}
                      </td>
                      <td className="py-3.5 pl-4 text-right whitespace-nowrap">
                        <div className="flex items-center justify-end gap-1.5">
                          <button
                            type="button"
                            onClick={() => setSelectedProjectModal(p)}
                            className="p-1.5 rounded-lg text-gray-500 hover:text-blue-600 hover:bg-blue-50 dark:hover:bg-blue-950/40 dark:text-gray-400 dark:hover:text-blue-300 transition-colors cursor-pointer"
                            title={`View details for ${p.name}`}
                          >
                            <Eye className="w-3.5 h-3.5" />
                          </button>
                          <button
                            type="button"
                            onClick={() => navigate(`/software-inventory?project=${encodeURIComponent(p.name)}`)}
                            className="px-2 py-1 text-[11px] font-semibold rounded-md text-blue-700 dark:text-blue-300 bg-blue-50 dark:bg-blue-950/40 hover:bg-blue-100 dark:hover:bg-blue-900/40 transition-colors cursor-pointer flex items-center gap-1"
                            title={`Inspect ${compCount} components`}
                          >
                            <Package className="w-3 h-3" />
                            <span>Components</span>
                          </button>
                          <button
                            type="button"
                            onClick={() => navigate(`/vulnerabilities?project=${encodeURIComponent(p.name)}`)}
                            className="px-2 py-1 text-[11px] font-semibold rounded-md text-rose-700 dark:text-rose-300 bg-rose-50 dark:bg-rose-950/40 hover:bg-rose-100 dark:hover:bg-rose-900/40 transition-colors cursor-pointer flex items-center gap-1"
                            title={`Inspect ${vulnCount} findings`}
                          >
                            <ShieldCheck className="w-3 h-3" />
                            <span>Vulns</span>
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            ) : null}
          </table>

          {projectsList.length === 0 && (
            <div className="py-12 text-center space-y-3">
              <div className="w-12 h-12 mx-auto rounded-full bg-gray-100 dark:bg-gray-800 flex items-center justify-center text-gray-400">
                <Search className="w-5 h-5" />
              </div>
              <div>
                <h4 className="text-sm font-bold text-gray-900 dark:text-white">
                  {loading ? 'Loading…' : 'No projects or microservices available yet.'}
                </h4>
                <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">{emptyMessage}</p>
              </div>
              <button
                onClick={() => {
                  setSearchQuery('');
                  setStatusFilter('All Statuses');
                  setSearchParams({}, { replace: true });
                }}
                className="px-3.5 py-1.5 bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 text-gray-700 dark:text-gray-300 text-xs font-semibold rounded-lg transition-colors cursor-pointer"
              >
                Reset Filters
              </button>
            </div>
          )}
        </div>

        {/* Systematic Pagination Controls (15, 20, 25, 50, 100) */}
        <TablePagination
          currentPage={safeCurrentPage}
          totalItems={totalItems}
          pageSize={pageSize}
          pageSizeOptions={[15, 20, 25, 50, 100]}
          onPageChange={(page) => setCurrentPage(page)}
          onPageSizeChange={(size) => {
            setPageSize(size);
            setCurrentPage(1);
          }}
          itemLabel="projects"
        />
      </div>

      {/* Project Details Modal */}
      {selectedProjectModal && (() => {
        const p = selectedProjectModal;
        const projectComps = (components || []).filter((c) => (c.project || '').toLowerCase().trim() === p.name.toLowerCase().trim());
        const compCount = p.component_count || (projectComps.length > 0 ? projectComps.length : p.scans);
        const projectVulns = (vulnerabilities || []).filter((v) => (v.project || '').toLowerCase().trim() === p.name.toLowerCase().trim());
        const vulnCount = p.vulns > 0 ? p.vulns : projectVulns.length;

        return (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4 animate-fadeIn">
            <div className="bg-white dark:bg-[#111827] rounded-xl max-w-xl w-full p-6 shadow-2xl border border-gray-200 dark:border-gray-800 space-y-4">
              <div className="flex items-start justify-between gap-3 pb-3 border-b border-gray-100 dark:border-gray-800">
                <div>
                  <div className="flex items-center gap-2 flex-wrap">
                    <h3 className="text-base font-bold text-gray-900 dark:text-white">
                      {p.name}
                    </h3>
                    <span className={`px-2.5 py-0.5 rounded text-[10px] font-bold border ${riskColor(p.risk)}`}>
                      {p.risk}
                    </span>
                  </div>
                  <p className="text-xs text-gray-500 mt-0.5">
                    {p.classifier} · Last scanned {relativeTime(p.last_scanned_at)}
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => setSelectedProjectModal(null)}
                  className="p-1 text-gray-400 hover:text-gray-600 dark:hover:text-gray-200 cursor-pointer"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              <div className="grid grid-cols-2 gap-3">
                {/* Components Card */}
                <div
                  onClick={() => {
                    setSelectedProjectModal(null);
                    navigate(`/software-inventory?project=${encodeURIComponent(p.name)}`);
                  }}
                  className="p-4 rounded-xl border border-blue-200/80 dark:border-blue-900/50 bg-blue-50/40 dark:bg-blue-950/20 hover:border-blue-400 transition-all cursor-pointer group flex flex-col justify-between shadow-2xs"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <div className="w-7 h-7 rounded-lg bg-blue-100 dark:bg-blue-900/60 text-blue-600 flex items-center justify-center">
                        <Package className="w-3.5 h-3.5" />
                      </div>
                      <span className="text-[10px] font-bold uppercase tracking-wider text-gray-600 dark:text-gray-300">
                        COMPONENTS
                      </span>
                    </div>
                    <ExternalLink className="w-3.5 h-3.5 text-gray-400 group-hover:text-blue-600 transition-colors" />
                  </div>
                  <div className="mt-3">
                    <h4 className="text-2xl font-black text-gray-900 dark:text-white group-hover:text-blue-600 transition-colors font-mono">
                      {compCount}
                    </h4>
                    <p className="text-[11px] text-blue-600 dark:text-blue-400 mt-1 font-semibold flex items-center gap-1">
                      <span>View in Software Inventory</span>
                      <span>→</span>
                    </p>
                  </div>
                </div>

                {/* Vulnerabilities Card */}
                <div
                  onClick={() => {
                    setSelectedProjectModal(null);
                    navigate(`/vulnerabilities?project=${encodeURIComponent(p.name)}`);
                  }}
                  className="p-4 rounded-xl border border-rose-200/80 dark:border-rose-900/50 bg-rose-50/40 dark:bg-rose-950/20 hover:border-rose-400 transition-all cursor-pointer group flex flex-col justify-between shadow-2xs"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <div className="w-7 h-7 rounded-lg bg-rose-100 dark:bg-rose-900/60 text-rose-600 flex items-center justify-center">
                        <ShieldCheck className="w-3.5 h-3.5" />
                      </div>
                      <span className="text-[10px] font-bold uppercase tracking-wider text-gray-600 dark:text-gray-300">
                        VULNERABILITIES
                      </span>
                    </div>
                    <ExternalLink className="w-3.5 h-3.5 text-gray-400 group-hover:text-rose-600 transition-colors" />
                  </div>
                  <div className="mt-3">
                    <h4 className={`text-2xl font-black font-mono transition-colors ${vulnCount > 0 ? 'text-red-600 dark:text-red-400' : 'text-gray-900 dark:text-white'}`}>
                      {vulnCount}
                    </h4>
                    <p className="text-[11px] text-rose-600 dark:text-rose-400 mt-1 font-semibold flex items-center gap-1">
                      <span>View in Vulnerability Management</span>
                      <span>→</span>
                    </p>
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-2 text-xs">
                <div className="rounded-lg bg-gray-50 dark:bg-gray-800/50 p-2.5">
                  <span className="text-[10px] uppercase text-gray-400 block font-semibold">Compliance</span>
                  <span className="font-bold text-gray-900 dark:text-white">{p.compliance}</span>
                </div>
                <div className="rounded-lg bg-gray-50 dark:bg-gray-800/50 p-2.5">
                  <span className="text-[10px] uppercase text-gray-400 block font-semibold">Total Scans Run</span>
                  <span className="font-bold text-gray-900 dark:text-white">{p.scans}</span>
                </div>
              </div>

              {/* Individual Microservices / Scans for this Project */}
              {(() => {
                const map = new Map<string, { app: string; scanId?: string; comps: number; vulns: number }>();
                (scansHistory || []).forEach(job => {
                  if ((job.targetProject || '').toLowerCase().trim() === p.name.toLowerCase().trim()) {
                    const app = job.appService || 'default';
                    const key = `${job.id || app}`;
                    map.set(key, {
                      app,
                      scanId: job.id,
                      comps: job.componentsFound || 0,
                      vulns: (job.criticals || 0) + (job.highs || 0) + (job.mediums || 0) + (job.lows || 0),
                    });
                  }
                });
                (components || []).forEach(c => {
                  if ((c.project || '').toLowerCase().trim() === p.name.toLowerCase().trim() && c.projectApplication) {
                    const app = c.projectApplication;
                    const key = `${c.scanId || app}`;
                    if (!map.has(key)) {
                      map.set(key, {
                        app,
                        scanId: c.scanId,
                        comps: 0,
                        vulns: 0,
                      });
                    }
                  }
                });
                const projectScans = Array.from(map.values()).map(item => {
                  const matchingComps = (components || []).filter(c =>
                    (c.project || '').toLowerCase().trim() === p.name.toLowerCase().trim() &&
                    (item.scanId ? c.scanId === item.scanId : (c.projectApplication || '').toLowerCase() === item.app.toLowerCase())
                  );
                  const matchingVulns = (vulnerabilities || []).filter(v =>
                    (v.project || '').toLowerCase().trim() === p.name.toLowerCase().trim() &&
                    (item.scanId ? v.scanId === item.scanId : (v.application || '').toLowerCase() === item.app.toLowerCase())
                  );
                  return {
                    app: item.app,
                    scanId: item.scanId,
                    comps: matchingComps.length > 0 ? matchingComps.length : item.comps,
                    vulns: matchingVulns.length > 0 ? matchingVulns.length : item.vulns,
                  };
                });

                if (projectScans.length === 0) return null;

                return (
                  <div className="space-y-2 pt-2 border-t border-gray-100 dark:border-gray-800">
                    <div className="flex items-center justify-between">
                      <span className="text-[11px] font-bold uppercase tracking-wider text-gray-500 dark:text-gray-400">
                        Microservices / Single Scans ({projectScans.length})
                      </span>
                      <span className="text-[10px] text-gray-400">Filter single scan findings</span>
                    </div>
                    <div className="divide-y divide-gray-100 dark:divide-gray-800 border border-gray-200 dark:border-gray-800 rounded-lg overflow-hidden bg-gray-50/50 dark:bg-gray-800/30">
                      {projectScans.map((scanItem, idx) => (
                        <div key={`${scanItem.app}-${idx}`} className="p-2.5 flex items-center justify-between gap-3 text-xs">
                          <div className="min-w-0 flex items-center gap-2">
                            <span className="w-1.5 h-1.5 rounded-full bg-blue-500 shrink-0" />
                            <span className="font-semibold text-gray-900 dark:text-white truncate">
                              {scanItem.app}
                            </span>
                          </div>
                          <div className="flex items-center gap-2 shrink-0">
                            <button
                              type="button"
                              onClick={() => {
                                setSelectedProjectModal(null);
                                const params = new URLSearchParams({
                                  project: p.name,
                                  app: scanItem.app,
                                });
                                if (scanItem.scanId) params.set('scan', scanItem.scanId);
                                navigate(`/software-inventory?${params.toString()}`);
                              }}
                              className="px-2 py-1 rounded bg-blue-50 dark:bg-blue-950/50 hover:bg-blue-100 text-blue-700 dark:text-blue-300 font-mono text-[11px] font-semibold transition-colors cursor-pointer"
                              title={`Filter inventory for ${scanItem.app}`}
                            >
                              {scanItem.comps} comps
                            </button>
                            <button
                              type="button"
                              onClick={() => {
                                setSelectedProjectModal(null);
                                const params = new URLSearchParams({
                                  project: p.name,
                                  app: scanItem.app,
                                });
                                if (scanItem.scanId) params.set('scan', scanItem.scanId);
                                navigate(`/vulnerabilities?${params.toString()}`);
                              }}
                              className={`px-2 py-1 rounded text-[11px] font-mono font-semibold transition-colors cursor-pointer ${
                                scanItem.vulns > 0
                                  ? 'bg-rose-50 dark:bg-rose-950/50 hover:bg-rose-100 text-rose-700 dark:text-rose-300'
                                  : 'bg-gray-100 dark:bg-gray-800 text-gray-500'
                              }`}
                              title={`Filter findings for ${scanItem.app}`}
                            >
                              {scanItem.vulns} vulns
                            </button>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                );
              })()}

              <div className="flex items-center justify-end gap-2 pt-3 border-t border-gray-100 dark:border-gray-800">
                <button
                  type="button"
                  onClick={() => setSelectedProjectModal(null)}
                  className="px-3.5 py-1.5 text-xs font-semibold rounded-lg border border-gray-200 dark:border-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-800 cursor-pointer"
                >
                  Close
                </button>
              </div>
            </div>
          </div>
        );
      })()}
    </div>
  );
};

export default ProjectsMicroservices;
