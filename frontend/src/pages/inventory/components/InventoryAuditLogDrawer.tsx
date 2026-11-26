import React from 'react';
import { createPortal } from 'react-dom';
import { ClipboardList, X } from 'lucide-react';
import type * as api from '../../../api/client';

interface InventoryAuditLogDrawerProps {
  showAuditLog: boolean;
  onClose: () => void;
  loadingAudit: boolean;
  auditItems: api.InventoryAuditLogItem[];
}

export const InventoryAuditLogDrawer: React.FC<InventoryAuditLogDrawerProps> = ({
  showAuditLog,
  onClose,
  loadingAudit,
  auditItems,
}) => {
  if (!showAuditLog) return null;

  return createPortal(
    <div className="fixed inset-0 z-[9999] w-screen h-screen flex justify-end bg-black/60 animate-fadeIn">
      <div className="absolute inset-0 cursor-pointer" onClick={onClose} />
      <div className="relative w-full max-w-2xl bg-white dark:bg-[#0f172a] shadow-2xl h-full flex flex-col border-l border-gray-200 dark:border-gray-800 z-10 animate-in slide-in-from-right duration-200">
        <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-800 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-indigo-50 dark:bg-indigo-950/60 text-indigo-600 dark:text-indigo-400">
              <ClipboardList className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-bold text-gray-900 dark:text-white">Inventory Audit Log</h3>
              <p className="text-xs text-gray-500 dark:text-gray-400 mt-0.5">
                Tracks manual additions, removals with reason, and automated scan closures
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

        <div className="flex-1 overflow-y-auto p-6 space-y-3">
          {loadingAudit ? (
            <div className="py-12 text-center text-xs text-gray-500">Loading audit log...</div>
          ) : auditItems.length === 0 ? (
            <div className="py-12 text-center text-xs text-gray-500">No audit log entries found.</div>
          ) : (
            auditItems.map((item) => (
              <div key={item.id} className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-xl p-4 shadow-xs space-y-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${item.action === 'ADD' ? 'bg-emerald-50 text-emerald-700 dark:bg-emerald-950/60 dark:text-emerald-300' :
                        item.action === 'REMOVE' ? 'bg-red-50 text-red-700 dark:bg-red-950/60 dark:text-red-300' :
                          item.action === 'VULN_STATUS_CHANGE' ? 'bg-purple-50 text-purple-700 dark:bg-purple-950/60 dark:text-purple-300' :
                            'bg-indigo-50 text-indigo-700 dark:bg-indigo-950/60 dark:text-indigo-300'
                      }`}>
                      {item.action === 'VULN_STATUS_CHANGE' ? 'VULN STATUS' : item.action}
                    </span>
                    <span className="text-xs font-semibold text-gray-900 dark:text-white">
                      {item.component_name} {item.action === 'VULN_STATUS_CHANGE' ? `→ ${item.component_version}` : `@ ${item.component_version}`}
                    </span>
                  </div>
                  <span className="text-[10px] text-gray-400">
                    {item.created_at ? new Date(item.created_at).toLocaleString() : ''}
                  </span>
                </div>
                <p className="text-xs text-gray-600 dark:text-gray-300">
                  <span className="text-gray-400">Reason: </span>
                  {item.reason || 'None provided'}
                </p>
                <div className="text-[10px] text-gray-400 flex items-center justify-between pt-1 border-t border-gray-100 dark:border-gray-800/60">
                  <span>By: {item.changed_by}</span>
                  <span>{item.application_id || 'System'}</span>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>,
    document.body
  );
};
