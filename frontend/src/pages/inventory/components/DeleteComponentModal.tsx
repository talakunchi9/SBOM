import React from 'react';
import { createPortal } from 'react-dom';
import { Trash2 } from 'lucide-react';

interface DeleteComponentModalProps {
  deleteTarget: { id: string; name: string; version: string } | null;
  deleteReason: string;
  onReasonChange: (val: string) => void;
  onCancel: () => void;
  onConfirm: () => void;
}

export const DeleteComponentModal: React.FC<DeleteComponentModalProps> = ({
  deleteTarget,
  deleteReason,
  onReasonChange,
  onCancel,
  onConfirm,
}) => {
  if (!deleteTarget) return null;

  return createPortal(
    <div className="fixed inset-0 z-[9999] w-screen h-screen flex items-center justify-center bg-black/60 p-4 animate-fadeIn overflow-y-auto">
      <div className="bg-white dark:bg-[#111827] rounded-2xl max-w-md w-full shadow-2xl border border-gray-100 dark:border-gray-800 overflow-hidden p-6 space-y-4">
        <div className="flex items-center gap-3 text-red-600 dark:text-red-400">
          <div className="p-2 rounded-xl bg-red-50 dark:bg-red-950/50">
            <Trash2 className="w-5 h-5" />
          </div>
          <h3 className="text-base font-semibold text-gray-900 dark:text-white">Delete Inventory Component</h3>
        </div>
        <p className="text-xs text-gray-600 dark:text-gray-300">
          You are removing <span className="font-semibold text-gray-900 dark:text-white">{deleteTarget.name}@{deleteTarget.version}</span>.
          Please provide a justification to record in the audit trail.
        </p>
        <div className="space-y-1.5">
          <label className="text-xs font-semibold text-gray-700 dark:text-gray-300">Reason for Removal *</label>
          <textarea
            rows={3}
            value={deleteReason}
            onChange={(e) => onReasonChange(e.target.value)}
            placeholder="e.g. Deprecated package replaced by native module / False positive"
            className="w-full text-xs px-3 py-2 rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900 text-gray-900 dark:text-gray-100 focus:outline-none focus:ring-2 focus:ring-red-500/20"
          />
        </div>
        <div className="flex items-center justify-end gap-2 pt-2">
          <button
            onClick={onCancel}
            className="px-3 py-1.5 text-xs font-medium text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-800 rounded-lg transition-colors cursor-pointer"
          >
            Cancel
          </button>
          <button
            disabled={!deleteReason.trim()}
            onClick={onConfirm}
            className="px-3.5 py-1.5 text-xs font-medium text-white bg-red-600 hover:bg-red-700 disabled:opacity-50 disabled:cursor-not-allowed rounded-lg transition-colors cursor-pointer shadow-sm"
          >
            Confirm Delete
          </button>
        </div>
      </div>
    </div>,
    document.body
  );
};
