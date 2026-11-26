import React from 'react';
import { createPortal } from 'react-dom';
import { FileCode, GitBranch, Layers, Search, X } from 'lucide-react';
import type * as api from '../../../api/client';

interface PackageOccurrencesDrawerProps {
  selectedPackage: string | null;
  onClose: () => void;
  loadingDrawer: boolean;
  drawerData: api.PackageOccurrencesResponse | null;
  drawerFilter: string;
  onFilterChange: (val: string) => void;
  filteredUsages: api.PackageOccurrenceUsage[];
}

export const PackageOccurrencesDrawer: React.FC<PackageOccurrencesDrawerProps> = ({
  selectedPackage,
  onClose,
  loadingDrawer,
  drawerData,
  drawerFilter,
  onFilterChange,
  filteredUsages,
}) => {
  if (!selectedPackage) return null;

  return createPortal(
    <div className="fixed inset-0 z-[9999] w-screen h-screen flex justify-end bg-black/60 animate-fadeIn">
      <div className="absolute inset-0 cursor-pointer" onClick={onClose} />
      <div className="relative w-full max-w-2xl bg-white dark:bg-[#0f172a] shadow-2xl h-full flex flex-col border-l border-gray-200 dark:border-gray-800 z-10 animate-in slide-in-from-right duration-200">
        {/* Header */}
        <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-800 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-indigo-50 dark:bg-indigo-950/60 text-indigo-600 dark:text-indigo-400">
              <Layers className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-lg font-bold font-mono text-gray-900 dark:text-white">
                  {selectedPackage}
                </span>
                <span className="text-[11px] font-semibold px-2 py-0.5 rounded-full bg-indigo-50 dark:bg-indigo-950/60 text-indigo-700 dark:text-indigo-300 border border-indigo-200 dark:border-indigo-800">
                  Occurrence Details
                </span>
              </div>
              <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                Cross-application usage distribution across all software inventories and scans
              </p>
            </div>
          </div>

          <button
            type="button"
            onClick={onClose}
            className="p-1.5 rounded-lg text-gray-400 hover:text-gray-600 dark:hover:text-gray-200 hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors cursor-pointer"
            title="Close"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Summary Metrics */}
        <div className="p-4 border-b border-gray-200 dark:border-gray-800 grid grid-cols-3 gap-3 bg-white dark:bg-[#111827]">
          <div className="p-3 rounded-xl bg-gray-50 dark:bg-gray-800/50 border border-gray-100 dark:border-gray-800">
            <span className="text-[10px] font-bold uppercase tracking-wider text-gray-400 block mb-0.5">
              Total Instances
            </span>
            <span className="text-xl font-bold font-mono text-indigo-600 dark:text-indigo-400">
              {loadingDrawer ? '...' : (drawerData?.occurrence_count ?? 0)}
            </span>
          </div>
          <div className="p-3 rounded-xl bg-gray-50 dark:bg-gray-800/50 border border-gray-100 dark:border-gray-800">
            <span className="text-[10px] font-bold uppercase tracking-wider text-gray-400 block mb-0.5">
              Applications
            </span>
            <span className="text-xl font-bold font-mono text-gray-900 dark:text-white">
              {loadingDrawer ? '...' : (drawerData?.applications_count ?? 0)}
            </span>
          </div>
          <div className="p-3 rounded-xl bg-gray-50 dark:bg-gray-800/50 border border-gray-100 dark:border-gray-800">
            <span className="text-[10px] font-bold uppercase tracking-wider text-gray-400 block mb-0.5">
              Modules
            </span>
            <span className="text-xl font-bold font-mono text-gray-900 dark:text-white">
              {loadingDrawer ? '...' : (drawerData?.modules_count ?? 0)}
            </span>
          </div>
        </div>

        {/* Filter Toolbar */}
        <div className="p-3 border-b border-gray-100 dark:border-gray-800 bg-gray-50/40 dark:bg-gray-900/20 flex items-center justify-between gap-3">
          <div className="relative flex-1">
            <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" />
            <input
              type="text"
              value={drawerFilter}
              onChange={(e) => onFilterChange(e.target.value)}
              placeholder="Filter by application, module, version, manifest path..."
              className="w-full text-xs pl-9 pr-3 py-1.5 rounded-lg border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 text-gray-900 dark:text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-indigo-500"
            />
          </div>
          <span className="text-xs text-gray-500 whitespace-nowrap">
            {filteredUsages.length} of {drawerData?.usages?.length ?? 0} usages
          </span>
        </div>

        {/* Drawer Table Scroll Area */}
        <div className="flex-1 overflow-y-auto p-4 space-y-4">
          {loadingDrawer ? (
            <div className="py-16 text-center text-gray-500 space-y-3">
              <div className="w-8 h-8 border-2 border-indigo-600 border-t-transparent rounded-full animate-spin mx-auto" />
              <p className="text-xs font-medium">Querying package occurrences across inventories...</p>
            </div>
          ) : filteredUsages.length === 0 ? (
            <div className="py-16 text-center text-gray-400 space-y-2">
              <p className="text-sm font-semibold">No occurrence records found</p>
              <p className="text-xs text-gray-500">
                No matching application modules found for the filter or this package.
              </p>
            </div>
          ) : (
            <div className="border border-gray-200 dark:border-gray-800 rounded-xl overflow-hidden shadow-2xs">
              <table className="w-full text-left text-xs">
                <thead className="bg-gray-50 dark:bg-gray-800 text-[10px] font-bold text-gray-400 uppercase tracking-wider border-b border-gray-200 dark:border-gray-700">
                  <tr>
                    <th className="p-3">Application</th>
                    <th className="p-3">Module</th>
                    <th className="p-3">Version</th>
                    <th className="p-3">Scope / Type</th>
                    <th className="p-3">Manifest Location</th>
                    <th className="p-3">Detection</th>
                    <th className="p-3">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100 dark:divide-gray-800">
                  {filteredUsages.map((u, i) => (
                    <tr key={`${u.application_id}-${u.module_id}-${i}`} className="hover:bg-gray-50/50 dark:hover:bg-gray-800/40">
                      <td className="p-3">
                        <span className="font-semibold text-gray-900 dark:text-white block">
                          {u.application_name || u.application_id || 'Unknown'}
                        </span>
                        {u.branch && (
                          <span className="text-[10px] text-gray-400 flex items-center gap-1 mt-0.5">
                            <GitBranch className="w-3 h-3" /> {u.branch}
                          </span>
                        )}
                      </td>
                      <td className="p-3 font-mono text-gray-700 dark:text-gray-300">
                        {u.module_name || u.module_id || '-'}
                      </td>
                      <td className="p-3 font-mono font-semibold text-indigo-600 dark:text-indigo-400">
                        {u.version || '-'}
                      </td>
                      <td className="p-3">
                        <div className="flex flex-col gap-1 items-start">
                          <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-blue-50 text-blue-700 dark:bg-blue-950/60 dark:text-blue-300 border border-blue-200 dark:border-blue-900">
                            {u.direct_dependency ? 'Direct' : 'Transitive'}
                          </span>
                          <span className="text-[10px] text-gray-500 uppercase font-mono">
                            {u.scope || 'runtime'}
                          </span>
                        </div>
                      </td>
                      <td className="p-3 font-mono text-gray-600 dark:text-gray-400 text-[11px]">
                        <div className="flex items-center gap-1.5" title={u.package_location || 'manifest'}>
                          <FileCode className="w-3.5 h-3.5 text-gray-400 shrink-0" />
                          <span className="truncate max-w-[140px]">{u.package_location || 'manifest'}</span>
                        </div>
                      </td>
                      <td className="p-3 font-mono text-[10px] text-gray-500 uppercase">
                        {u.detection_method || 'cyclonedx'}
                      </td>
                      <td className="p-3">
                        <span className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold ${
                          u.status?.toLowerCase() === 'removed'
                            ? 'bg-rose-50 text-rose-700 dark:bg-rose-950/60 dark:text-rose-300 border border-rose-200 dark:border-rose-900'
                            : 'bg-emerald-50 text-emerald-700 dark:bg-emerald-950/60 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-900'
                        }`}>
                          {u.status || 'Active'}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>,
    document.body
  );
};
