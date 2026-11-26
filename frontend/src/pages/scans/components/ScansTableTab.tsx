import React from 'react';
import { Filter, FolderGit2, Play, RotateCcw, Search, User } from 'lucide-react';
import type { ScanJob } from '../../../types';
import { displayStatus, formatScanTimestamp12h } from '../scanProgress';
import { ScanActionMenu } from '../ScanActionMenu';
import { TablePagination } from '../../../components/common/TablePagination';

interface ScansTableTabProps {
  scanSearch: string;
  onScanSearchChange: (val: string) => void;
  showScanFilters: boolean;
  onToggleScanFilters: () => void;
  scanStatusFilter: string;
  onScanStatusFilterChange: (val: string) => void;
  scanTypeFilter: string;
  onScanTypeFilterChange: (val: string) => void;
  onResetFilters: () => void;
  onLaunchScan: () => void;
  filteredScans: ScanJob[];
  paginatedScans: ScanJob[];
  safeScanPage: number;
  totalScans: number;
  scanPageSize: number;
  onPageChange: (page: number) => void;
  onPageSizeChange: (size: number) => void;
  rescanningId: string | null;
  onSelectScan: (scanId: string) => void;
  onExport: (format: 'spdx' | 'cyclonedx' | 'csv' | 'json', scanId?: string) => void;
  onRescan: (scan: ScanJob) => void;
  onToggleLifecycle: (scan: ScanJob, newStatus: 'Active' | 'Decommissioned') => void;
}

export const ScansTableTab: React.FC<ScansTableTabProps> = ({
  scanSearch,
  onScanSearchChange,
  showScanFilters,
  onToggleScanFilters,
  scanStatusFilter,
  onScanStatusFilterChange,
  scanTypeFilter,
  onScanTypeFilterChange,
  onResetFilters,
  onLaunchScan,
  filteredScans,
  paginatedScans,
  safeScanPage,
  totalScans,
  scanPageSize,
  onPageChange,
  onPageSizeChange,
  rescanningId,
  onSelectScan,
  onExport,
  onRescan,
  onToggleLifecycle,
}) => {
  return (
    <div className="space-y-6">
      {/* Search & Action Bar */}
      <div className="bg-white dark:bg-[#111827] border border-gray-200 dark:border-gray-800 rounded-xl p-4 shadow-2xs space-y-3">
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
          {/* Left: Search Input & Filter Toggle */}
          <div className="flex items-center gap-2 flex-1 max-w-xl">
            <div className="relative flex-1">
              <Search className="w-4 h-4 text-gray-400 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
              <input
                type="text"
                value={scanSearch}
                onChange={(e) => onScanSearchChange(e.target.value)}
                placeholder="Search by project name, application, scan type, status, or requester..."
                className="w-full pl-9 pr-4 py-2 text-xs bg-gray-50/70 dark:bg-gray-800/80 border border-gray-200 dark:border-gray-700 rounded-lg text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 hover:border-blue-300 dark:hover:border-blue-700 transition-colors shadow-2xs"
              />
            </div>

            {/* Filter Toggle Button */}
            <button
              type="button"
              onClick={onToggleScanFilters}
              className={`px-3 py-2 text-xs font-semibold rounded-lg border transition-all flex items-center gap-1.5 cursor-pointer shadow-2xs shrink-0 ${showScanFilters || scanStatusFilter !== 'All' || scanTypeFilter !== 'All'
                ? 'bg-blue-50 dark:bg-blue-950/60 border-blue-400 dark:border-blue-600 text-blue-600 dark:text-blue-400'
                : 'bg-white dark:bg-gray-800 border-gray-200 dark:border-gray-700 text-gray-700 dark:text-gray-300 hover:border-blue-300 dark:hover:border-blue-700 hover:text-blue-600'
                }`}
              title="Toggle Filters"
            >
              <Filter className="w-3.5 h-3.5" />
              <span>Filters</span>
              {(scanStatusFilter !== 'All' || scanTypeFilter !== 'All') && (
                <span className="w-2 h-2 rounded-full bg-blue-600 shrink-0" />
              )}
            </button>
          </div>

          {/* Right: ONLY ONE BUTTON: Launch Scan */}
          <div className="flex items-center gap-2 shrink-0 flex-wrap justify-end">
            <button
              onClick={onLaunchScan}
              className="px-3.5 py-2 text-xs font-bold text-white bg-gradient-to-r from-blue-600 to-blue-700 hover:from-blue-700 hover:to-blue-800 rounded-lg flex items-center gap-1.5 shadow-sm shadow-blue-500/20 cursor-pointer transition-all whitespace-nowrap"
              title="Launch Security Scan"
            >
              <Play className="w-3.5 h-3.5 shrink-0 fill-white" />
              <span>Launch Scan</span>
            </button>
          </div>
        </div>

        {/* Filter Dropdowns revealed upon clicking Filter icon */}
        {showScanFilters && (
          <div className="p-3 bg-gray-50/90 dark:bg-gray-800/60 border border-gray-200/80 dark:border-gray-700/80 rounded-lg flex flex-col sm:flex-row sm:items-center justify-between gap-3 animate-fadeIn">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-[11px] font-bold text-gray-500 dark:text-gray-400 uppercase tracking-wider mr-1">
                Filter by:
              </span>

              <select
                value={scanStatusFilter}
                onChange={(e) => onScanStatusFilterChange(e.target.value)}
                className="text-xs px-2.5 py-1.5 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg text-gray-700 dark:text-gray-300 cursor-pointer focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 shadow-2xs hover:border-blue-300 transition-colors"
              >
                <option value="All">All Statuses</option>
                <option value="completed">Completed</option>
                <option value="running">Running</option>
                <option value="queued">Queued</option>
                <option value="failed">Failed</option>
                <option value="cancelled">Cancelled</option>
              </select>

              <select
                value={scanTypeFilter}
                onChange={(e) => onScanTypeFilterChange(e.target.value)}
                className="text-xs px-2.5 py-1.5 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg text-gray-700 dark:text-gray-300 cursor-pointer focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 shadow-2xs hover:border-blue-300 transition-colors"
              >
                <option value="All">All Scan Types</option>
                <option value="Local Source">Local Source</option>
                <option value="Remote Git">Remote Git</option>
                <option value="Bulk Scan">Bulk Scan</option>
              </select>

              <button
                onClick={onResetFilters}
                className="px-2.5 py-1.5 text-xs font-semibold text-gray-600 hover:text-red-600 dark:text-gray-300 dark:hover:text-red-400 bg-white dark:bg-gray-800 hover:bg-red-50 dark:hover:bg-red-950/40 border border-gray-200 dark:border-gray-700 rounded-lg flex items-center gap-1.5 cursor-pointer transition-colors shadow-2xs ml-1"
                title="Reset Filters"
              >
                <RotateCcw className="w-3 h-3 text-gray-400" />
                <span>Reset</span>
              </button>
            </div>
          </div>
        )}

        {/* Table View */}
        <div className="overflow-x-auto rounded-lg border border-gray-100 dark:border-gray-800">
          <table className="w-full text-left text-xs min-w-[1200px]">
            <thead>
              <tr className="bg-slate-50/90 dark:bg-slate-800/70 text-slate-600 dark:text-slate-300 border-b border-slate-200/80 dark:border-slate-700/80">
                <th className="w-[22%] min-w-[200px] py-3.5 pl-5 pr-3 font-bold uppercase tracking-wider text-[11px] whitespace-nowrap">APPLICATION NAME</th>
                <th className="w-[14%] min-w-[130px] py-3.5 px-4 font-bold uppercase tracking-wider text-[11px] whitespace-nowrap">MODULE NAME</th>
                <th className="w-[15%] min-w-[150px] py-3.5 px-4 font-bold uppercase tracking-wider text-[11px] whitespace-nowrap">SCAN DATE</th>
                <th className="w-[13%] min-w-[130px] py-3.5 px-4 font-bold uppercase tracking-wider text-[11px] whitespace-nowrap">SCAN STATUS</th>
                <th className="w-[11%] min-w-[110px] py-3.5 px-4 font-bold uppercase tracking-wider text-[11px] whitespace-nowrap">SCAN TYPE</th>
                <th className="w-[11%] min-w-[120px] py-3.5 px-4 font-bold uppercase tracking-wider text-[11px] whitespace-nowrap">LIFECYCLE STATUS</th>
                <th className="w-[10%] min-w-[120px] py-3.5 px-4 font-bold uppercase tracking-wider text-[11px] whitespace-nowrap">CREATED BY</th>
                <th className="w-[4%] min-w-[70px] py-3.5 pr-5 pl-3 font-bold uppercase tracking-wider text-[11px] text-right whitespace-nowrap">ACTIONS</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100 dark:divide-gray-800">
              {filteredScans.length > 0 ? (
                paginatedScans.map((s) => (
                  <tr key={s.id} className="hover:bg-blue-50/40 dark:hover:bg-blue-950/20 transition-colors">
                    {/* APPLICATION NAME */}
                    <td className="py-3.5 pl-5 pr-3 whitespace-nowrap">
                      <div className="flex items-center gap-2">
                        <FolderGit2 className="w-3.5 h-3.5 text-blue-500 shrink-0" />
                        <span
                          onClick={() => onSelectScan(s.id)}
                          className="font-bold text-gray-900 dark:text-white hover:text-blue-600 dark:hover:text-blue-400 cursor-pointer"
                          title={`View ${s.targetProject} details`}
                        >
                          {s.targetProject}
                        </span>
                      </div>
                    </td>

                    {/* MODULE NAME */}
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-medium bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-700 font-mono">
                        {s.appService || '—'}
                      </span>
                    </td>

                    {/* SCAN DATE */}
                    <td className="py-3.5 px-4 text-gray-600 dark:text-gray-400 font-mono text-[11px] whitespace-nowrap">
                      {formatScanTimestamp12h(s.timestamp)}
                    </td>

                    {/* SCAN STATUS */}
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider ${s.status === 'completed'
                        ? 'bg-emerald-50 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800/60'
                        : s.status === 'running' || s.status === 'analyzing'
                          ? 'bg-blue-50 dark:bg-blue-950/60 text-blue-700 dark:text-blue-300 border border-blue-200 dark:border-blue-800/60 animate-pulse'
                          : s.status === 'failed'
                            ? 'bg-red-50 dark:bg-red-950/60 text-red-700 dark:text-red-300 border border-red-200 dark:border-red-800/60'
                            : s.status === 'cancelled'
                              ? 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 border border-slate-200 dark:border-slate-700'
                              : 'bg-amber-50 dark:bg-amber-950/60 text-amber-700 dark:text-amber-300 border border-amber-200 dark:border-amber-800/60'
                        }`}>
                        {s.status === 'running' || s.status === 'analyzing' ? (
                          <span className="w-1.5 h-1.5 rounded-full bg-blue-600 animate-ping" />
                        ) : s.status === 'completed' ? (
                          <span className="w-1.5 h-1.5 rounded-full bg-emerald-600" />
                        ) : s.status === 'cancelled' ? (
                          <span className="w-1.5 h-1.5 rounded-full bg-slate-400" />
                        ) : s.status === 'failed' ? (
                          <span className="w-1.5 h-1.5 rounded-full bg-red-600" />
                        ) : (
                          <span className="w-1.5 h-1.5 rounded-full bg-amber-500" />
                        )}
                        {displayStatus(s.status)}
                        {(s.status === 'running' || s.status === 'analyzing') && ` ${s.progress}%`}
                      </span>
                    </td>

                    {/* SCAN TYPE */}
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      <span className="px-2 py-0.5 rounded text-[11px] font-medium bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300 border border-gray-200 dark:border-gray-700">
                        {s.scanType}
                      </span>
                    </td>

                    {/* LIFECYCLE STATUS */}
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      {(() => {
                        const statusStr = (s.lifecycleStatus || 'Active').trim();
                        const isDecom = statusStr.toLowerCase() === 'decommissioned' || statusStr.toLowerCase() === 'inactive';
                        const isActive = !isDecom;
                        return (
                          <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider ${
                            isActive
                              ? 'bg-emerald-50 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800/60'
                              : 'bg-slate-100 dark:bg-slate-800/80 text-slate-700 dark:text-slate-300 border border-slate-300 dark:border-slate-700'
                          }`}>
                            <span className={`w-1.5 h-1.5 rounded-full ${isActive ? 'bg-emerald-500' : 'bg-slate-500'}`} />
                            {isActive ? 'Active' : 'Decommissioned'}
                          </span>
                        );
                      })()}
                    </td>

                    {/* SCAN REQUESTED BY */}
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      <div className="flex items-center gap-1.5">
                        <div className="w-5 h-5 rounded-full bg-blue-100 dark:bg-blue-900/60 text-blue-700 dark:text-blue-300 flex items-center justify-center text-[10px] font-bold shrink-0">
                          <User className="w-3 h-3" />
                        </div>
                        <span className="text-gray-700 dark:text-gray-300 font-medium text-xs">
                          {(s as any).requestedBy || (s as any).createdBy || 'Asha Mehta'}
                        </span>
                      </div>
                    </td>

                    {/* ACTIONS */}
                    <td className="py-3.5 pr-5 pl-3 text-right whitespace-nowrap">
                      <div className="inline-flex items-center justify-end">
                        <ScanActionMenu
                          scan={s}
                          onViewDetails={(scan) => onSelectScan(scan.id)}
                          onExport={(format, scanId) => onExport(format, scanId)}
                          onRescan={onRescan}
                          onToggleLifecycle={onToggleLifecycle}
                          rescanning={rescanningId === s.id}
                        />
                      </div>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={8} className="py-8 px-4 text-center">
                    <div className="flex flex-col items-center justify-center space-y-2">
                      <div className="w-10 h-10 rounded-full bg-gray-100 dark:bg-gray-800 text-gray-400 flex items-center justify-center shadow-2xs">
                        <Search className="w-5 h-5" />
                      </div>
                      <div className="max-w-md mx-auto">
                        <h4 className="text-sm font-bold text-gray-900 dark:text-white">
                          No security scans available yet.
                        </h4>
                        <p className="text-xs text-gray-500 dark:text-gray-400 mt-1 leading-relaxed">
                          No scan records found. Real security scans will appear once analysis is launched.
                        </p>
                      </div>
                      {(scanSearch || scanStatusFilter !== 'All' || scanTypeFilter !== 'All') && (
                        <button
                          onClick={onResetFilters}
                          className="mt-1 px-3.5 py-1.5 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-750 text-xs font-semibold rounded-lg shadow-2xs cursor-pointer inline-flex items-center gap-1.5"
                        >
                          Clear Filters
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Systematic Pagination Controls */}
        <TablePagination
          currentPage={safeScanPage}
          totalItems={totalScans}
          pageSize={scanPageSize}
          pageSizeOptions={[15, 20, 25, 50, 100]}
          onPageChange={onPageChange}
          onPageSizeChange={(size) => {
            onPageSizeChange(size);
            onPageChange(1);
          }}
          itemLabel="scans"
        />
      </div>
    </div>
  );
};
