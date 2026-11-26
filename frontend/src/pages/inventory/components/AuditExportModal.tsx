import React from 'react';
import { createPortal } from 'react-dom';
import { CheckCircle2, Download, ShieldCheck, X } from 'lucide-react';

interface AuditExportModalProps {
  isOpen: boolean;
  onClose: () => void;
  componentsCount: number;
  onDownload: () => void;
}

export const AuditExportModal: React.FC<AuditExportModalProps> = ({
  isOpen,
  onClose,
  componentsCount,
  onDownload,
}) => {
  if (!isOpen) return null;

  return createPortal(
    <div className="fixed inset-0 z-[9999] w-screen h-screen flex items-center justify-center bg-black/60 p-4 animate-fadeIn overflow-y-auto">
      <div className="bg-white dark:bg-[#111827] rounded-2xl max-w-lg w-full shadow-2xl border border-gray-100 dark:border-gray-800 overflow-hidden">
        {/* Modal Header */}
        <div className="px-6 py-5 border-b border-gray-100 dark:border-gray-800 flex items-center justify-between">
          <div className="flex items-center gap-3.5">
            <div className="w-10 h-10 rounded-xl bg-emerald-50 dark:bg-emerald-950/60 text-emerald-600 dark:text-emerald-400 flex items-center justify-center border border-emerald-100 dark:border-emerald-900/60 shadow-xs shrink-0">
              <ShieldCheck className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-bold text-gray-900 dark:text-white tracking-tight">
                Regulatory Audit Dossier Export
              </h3>
              <p className="text-xs text-gray-500 dark:text-gray-400 mt-0.5">
                Signed compliance package for CERT-In, ISO 27001, and SOC 2
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="p-1.5 rounded-lg text-gray-400 hover:text-gray-700 dark:hover:text-gray-200 hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors cursor-pointer"
            title="Close"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 space-y-4">
          <p className="text-xs text-gray-600 dark:text-gray-300 leading-relaxed">
            Generate an audit-ready compliance package containing cryptographic SBOM attestations, NTIA minimum elements verification, and vulnerability mitigation records.
          </p>

          <div className="space-y-2.5 bg-gray-50/80 dark:bg-gray-800/60 p-4 rounded-xl border border-gray-200/80 dark:border-gray-700/80 text-xs">
            <div className="flex justify-between items-center py-0.5">
              <span className="text-gray-500 dark:text-gray-400 font-medium">Compliance Target:</span>
              <span className="font-bold text-gray-900 dark:text-white">CERT-In / ISO 27001 / SOC 2</span>
            </div>
            <div className="flex justify-between items-center py-0.5">
              <span className="text-gray-500 dark:text-gray-400 font-medium">Components Included:</span>
              <span className="font-semibold text-gray-900 dark:text-white">{componentsCount} Normalized P-URLs</span>
            </div>
            <div className="flex justify-between items-center py-0.5">
              <span className="text-gray-500 dark:text-gray-400 font-medium">Cryptographic Signing:</span>
              <span className="font-semibold text-emerald-600 dark:text-emerald-400 flex items-center gap-1">
                <CheckCircle2 className="w-3.5 h-3.5" />
                <span>NIST P-256 Verified</span>
              </span>
            </div>
          </div>
        </div>

        {/* Modal Footer */}
        <div className="px-6 py-4 bg-gray-50/70 dark:bg-gray-850/70 border-t border-gray-100 dark:border-gray-800 flex items-center justify-end gap-3">
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2 text-xs font-semibold text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-xl hover:bg-gray-50 dark:hover:bg-gray-750 transition-colors cursor-pointer shadow-2xs"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={onDownload}
            className="px-5 py-2 text-xs font-bold text-white bg-gradient-to-r from-emerald-600 to-emerald-700 hover:from-emerald-700 hover:to-emerald-800 rounded-xl shadow-md shadow-emerald-500/20 flex items-center gap-2 cursor-pointer transition-all"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Generate & Download</span>
          </button>
        </div>
      </div>
    </div>,
    document.body
  );
};
