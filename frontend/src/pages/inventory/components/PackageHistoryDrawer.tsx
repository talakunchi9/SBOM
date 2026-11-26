import React from 'react';
import { createPortal } from 'react-dom';
import { History, X } from 'lucide-react';
import type * as api from '../../../api/client';

interface PackageHistoryDrawerProps {
  historyPackage: string | null;
  onClose: () => void;
  loadingHistory: boolean;
  historyData: api.PackageHistoryResponse | null;
}

export const PackageHistoryDrawer: React.FC<PackageHistoryDrawerProps> = ({
  historyPackage,
  onClose,
  loadingHistory,
  historyData,
}) => {
  if (!historyPackage) return null;

  return createPortal(
    <div className="fixed inset-0 z-[9999] w-screen h-screen flex justify-end bg-black/60 animate-fadeIn">
      <div className="absolute inset-0 cursor-pointer" onClick={onClose} />
      <div className="relative w-full max-w-2xl bg-white dark:bg-[#0f172a] shadow-2xl h-full flex flex-col border-l border-gray-200 dark:border-gray-800 z-10 animate-in slide-in-from-right duration-200">
        {/* Header */}
        <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-800 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-blue-50 dark:bg-blue-950/60 text-blue-600 dark:text-blue-400">
              <History className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-bold text-gray-900 dark:text-white flex items-center gap-2">
                {historyPackage}
                <span className="text-xs px-2 py-0.5 rounded-full bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-300 font-normal">
                  Version Timeline
                </span>
              </h3>
              <p className="text-xs text-gray-500 dark:text-gray-400 mt-0.5">
                Chronological evolution across scans, upgrades, and manual overrides
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-gray-400 hover:text-gray-600 dark:hover:text-gray-200 hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Summary Cards */}
        <div className="p-6 border-b border-gray-200 dark:border-gray-800 bg-gray-50/50 dark:bg-gray-900/30 grid grid-cols-3 gap-3">
          <div className="bg-white dark:bg-gray-900 p-3 rounded-xl border border-gray-200 dark:border-gray-800 shadow-xs">
            <span className="text-[11px] text-gray-500 dark:text-gray-400">Total Events</span>
            <p className="text-lg font-bold text-gray-900 dark:text-white mt-0.5">{historyData?.total_events || 0}</p>
          </div>
          <div className="bg-white dark:bg-gray-900 p-3 rounded-xl border border-gray-200 dark:border-gray-800 shadow-xs">
            <span className="text-[11px] text-gray-500 dark:text-gray-400">Distinct Versions</span>
            <p className="text-lg font-bold text-blue-600 dark:text-blue-400 mt-0.5">{historyData?.distinct_versions?.length || 0}</p>
          </div>
          <div className="bg-white dark:bg-gray-900 p-3 rounded-xl border border-gray-200 dark:border-gray-800 shadow-xs">
            <span className="text-[11px] text-gray-500 dark:text-gray-400">Latest Version</span>
            <p className="text-sm font-bold text-emerald-600 dark:text-emerald-400 mt-1 truncate">
              {historyData?.distinct_versions && historyData.distinct_versions.length > 0
                ? historyData.distinct_versions[historyData.distinct_versions.length - 1]
                : 'N/A'}
            </p>
          </div>
        </div>

        {/* Timeline List */}
        <div className="flex-1 overflow-y-auto p-6 space-y-4">
          {loadingHistory ? (
            <div className="py-12 text-center text-xs text-gray-500">Loading version history...</div>
          ) : (!historyData || historyData.timeline.length === 0) ? (
            <div className="py-12 text-center text-xs text-gray-500">No historical events recorded for this package.</div>
          ) : (
            <div className="relative pl-6 space-y-6 before:absolute before:left-2 before:top-2 before:bottom-2 before:w-0.5 before:bg-gray-200 dark:before:bg-gray-800">
              {historyData.timeline.map((evt, idx) => {
                const isUpgraded = evt.change_type === 'UPGRADED';
                const isAdded = evt.change_type === 'ADDED';
                const isRemove = evt.change_type === 'REMOVE';

                let badgeColor = 'bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-300';
                if (isUpgraded) badgeColor = 'bg-blue-50 text-blue-700 dark:bg-blue-950/60 dark:text-blue-300 border border-blue-200 dark:border-blue-900';
                else if (isAdded) badgeColor = 'bg-emerald-50 text-emerald-700 dark:bg-emerald-950/60 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-900';
                else if (isRemove) badgeColor = 'bg-red-50 text-red-700 dark:bg-red-950/60 dark:text-red-300 border border-red-200 dark:border-red-900';

                return (
                  <div key={idx} className="relative group">
                    <div className={`absolute -left-[27px] top-1.5 w-3 h-3 rounded-full border-2 bg-white dark:bg-[#0f172a] ${isUpgraded ? 'border-blue-500' : isAdded ? 'border-emerald-500' : isRemove ? 'border-red-500' : 'border-gray-400'
                      }`} />
                    <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-xl p-3.5 shadow-xs space-y-2">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${badgeColor}`}>
                            {evt.change_type}
                          </span>
                          <span className="text-xs font-mono font-semibold text-gray-900 dark:text-white">
                            v{evt.version}
                          </span>
                          {evt.previous_version && (
                            <span className="text-[10px] text-gray-400">
                              (from v{evt.previous_version})
                            </span>
                          )}
                        </div>
                        <span className="text-[10px] text-gray-400">
                          {evt.timestamp ? new Date(evt.timestamp).toLocaleString() : ''}
                        </span>
                      </div>

                      <div className="text-xs text-gray-600 dark:text-gray-300 space-y-1">
                        <div className="flex items-center gap-2">
                          <span className="text-gray-400">Scope:</span>
                          <span className="font-medium text-gray-900 dark:text-gray-200">{evt.application} / {evt.module}</span>
                        </div>
                        {evt.source_manifest && (
                          <div className="flex items-center gap-2">
                            <span className="text-gray-400">Manifest:</span>
                            <span className="font-mono text-[11px] text-gray-500">{evt.source_manifest}</span>
                          </div>
                        )}
                        {evt.reason && (
                          <div className="flex items-start gap-2 pt-1 border-t border-gray-100 dark:border-gray-800/60">
                            <span className="text-gray-400">Note:</span>
                            <span className="text-gray-700 dark:text-gray-300 italic">{evt.reason}</span>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>,
    document.body
  );
};
