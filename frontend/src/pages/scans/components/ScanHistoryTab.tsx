import React from 'react';
import { useNavigate } from 'react-router-dom';
import { ExternalLink, Search } from 'lucide-react';
import type { ScanJob } from '../../../types';
import { formatScanTimestamp12h } from '../scanProgress';
import { ScanActionMenu } from '../ScanActionMenu';

interface ScanHistoryTabProps {
  historySearch: string;
  onHistorySearchChange: (val: string) => void;
  historyStatusFilter: string;
  onHistoryStatusFilterChange: (val: string) => void;
  filteredHistory: ScanJob[];
  rescanningId: string | null;
  onSelectScan: (scanId: string) => void;
  onExport: (format: 'spdx' | 'cyclonedx' | 'csv' | 'json', scanId?: string) => void;
  onRescan: (scan: ScanJob) => void;
  onToggleLifecycle: (scan: ScanJob, newStatus: 'Active' | 'Decommissioned') => void;
}

export const ScanHistoryTab: React.FC<ScanHistoryTabProps> = ({
  historySearch,
  onHistorySearchChange,
  historyStatusFilter,
  onHistoryStatusFilterChange,
  filteredHistory,
  rescanningId,
  onSelectScan,
  onExport,
  onRescan,
  onToggleLifecycle,
}) => {
  const navigate = useNavigate();

  return (
    <div className="space-y-6">
      <div className="bg-white dark:bg-[#111827] border border-gray-200 dark:border-gray-800 rounded-xl p-5 shadow-2xs space-y-4">
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
          <div className="relative flex-1 max-w-md">
            <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" />
            <input
              type="text"
              value={historySearch}
              onChange={(e) => onHistorySearchChange(e.target.value)}
              placeholder="Filter by Job ID or project..."
              className="w-full pl-9 pr-3 py-1.5 text-xs bg-gray-50 dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg text-gray-900 dark:text-white focus:ring-1 focus:ring-blue-500"
            />
          </div>

          <select
            value={historyStatusFilter}
            onChange={(e) => onHistoryStatusFilterChange(e.target.value)}
            className="text-xs px-3 py-1.5 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg text-gray-700 dark:text-gray-300"
          >
            <option value="All">All Statuses</option>
            <option value="completed">Completed</option>
            <option value="failed">Failed</option>
            <option value="cancelled">Cancelled</option>
            <option value="running">Running</option>
            <option value="queued">Queued</option>
          </select>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs min-w-[1100px]">
            <thead>
              <tr className="text-gray-500 dark:text-gray-400 border-b border-gray-100 dark:border-gray-800">
                {/* UUID intentionally hidden from UI */}
                <th className="py-3 px-3 font-semibold whitespace-nowrap">PROJECT & TAG</th>
                <th className="py-3 px-3 font-semibold whitespace-nowrap">SOURCE</th>
                <th className="py-3 px-3 font-semibold whitespace-nowrap">STATUS</th>
                <th className="py-3 px-3 font-semibold whitespace-nowrap">SUBMITTED</th>
                <th className="py-3 px-3 font-semibold whitespace-nowrap">CREATED BY</th>
                <th className="py-3 px-3 font-semibold whitespace-nowrap">COMPONENTS</th>
                <th className="py-3 px-3 font-semibold whitespace-nowrap">FINDINGS</th>
                <th className="py-3 pr-4 pl-3 font-semibold text-right whitespace-nowrap">ACTION</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100 dark:divide-gray-800">
              {filteredHistory.map((job) => (
                <tr key={job.id} className="hover:bg-gray-50/70 dark:hover:bg-gray-800/40">
                  {/* UUID intentionally hidden from UI */}
                  <td className="py-3">
                    <span className="font-bold text-gray-900 dark:text-white block">{job.targetProject}</span>
                    <span className="text-[10px] text-gray-400 font-mono">{job.releaseTag || 'v1.0.0'}</span>
                  </td>
                  <td className="py-3 text-gray-600 dark:text-gray-400 max-w-[180px] truncate" title={job.source}>
                    {job.source}
                  </td>
                  <td className="py-3">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${job.status === 'completed'
                      ? 'bg-emerald-50 text-emerald-700 dark:bg-emerald-950/60 dark:text-emerald-300'
                      : job.status === 'failed'
                        ? 'bg-red-50 text-red-700 dark:bg-red-950/60 dark:text-red-300'
                        : job.status === 'cancelled'
                          ? 'bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-300'
                          : job.status === 'running' || job.status === 'analyzing'
                            ? 'bg-blue-50 text-blue-700 dark:bg-blue-950/60 dark:text-blue-300'
                            : 'bg-amber-50 text-amber-700 dark:bg-amber-950/60 dark:text-amber-300'
                      }`}>
                      {job.status}
                    </span>
                  </td>
                  <td className="py-3 text-gray-500 dark:text-gray-400 font-mono text-[11px] whitespace-nowrap">{formatScanTimestamp12h(job.timestamp)}</td>
                  <td className="py-3 text-gray-700 dark:text-gray-300 font-medium">
                    {(job as any).requestedBy || (job as any).createdBy || 'Asha Mehta'}
                  </td>
                  <td className="py-3 font-semibold text-gray-900 dark:text-white">
                    <button
                      type="button"
                      onClick={() => {
                        const params = new URLSearchParams();
                        params.set('project', job.targetProject);
                        if (job.id) params.set('scan', job.id);
                        if (job.appService) params.set('app', job.appService);
                        navigate(`/software-inventory?${params.toString()}`);
                      }}
                      className="hover:underline hover:text-blue-600 dark:hover:text-blue-400 cursor-pointer text-left"
                      title={`View components for ${job.targetProject}${job.appService ? ` (${job.appService})` : ''} in Software Inventory`}
                    >
                      {job.componentsFound}
                    </button>
                  </td>
                  <td className="py-3">
                    <button
                      type="button"
                      onClick={() => {
                        const params = new URLSearchParams();
                        params.set('project', job.targetProject);
                        if (job.id) params.set('scan', job.id);
                        if (job.appService) params.set('app', job.appService);
                        navigate(`/vulnerabilities?${params.toString()}`);
                      }}
                      className="text-left hover:underline cursor-pointer group flex items-center gap-1.5"
                      title={`View findings for ${job.targetProject}${job.appService ? ` (${job.appService})` : ''} in Vulnerability Management`}
                    >
                      <span>
                        <span className="text-red-600 dark:text-red-400 font-semibold">{job.criticals || 0} Crit</span> •{' '}
                        <span className="text-orange-500 dark:text-orange-400 font-semibold">{job.highs || 0} High</span> •{' '}
                        <span className="text-amber-500 dark:text-amber-400 font-semibold">{job.mediums || 0} Med</span> •{' '}
                        <span className="text-sky-500 dark:text-sky-400 font-semibold">{job.lows || 0} Low</span>
                      </span>
                      <ExternalLink className="w-3 h-3 text-gray-400 opacity-0 group-hover:opacity-100 transition-opacity shrink-0" />
                    </button>
                  </td>
                  <td className="py-3 text-right">
                    <div className="inline-flex items-center justify-end">
                      <ScanActionMenu
                        scan={job}
                        onViewDetails={(scan) => onSelectScan(scan.id)}
                        onExport={(format, scanId) => onExport(format, scanId)}
                        onRescan={onRescan}
                        onToggleLifecycle={onToggleLifecycle}
                        rescanning={rescanningId === job.id}
                      />
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
