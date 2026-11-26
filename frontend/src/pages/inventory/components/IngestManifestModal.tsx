import React from 'react';
import { createPortal } from 'react-dom';
import { CheckCircle2, FileCode, Upload, X } from 'lucide-react';

interface IngestManifestModalProps {
  isOpen: boolean;
  onClose: () => void;
  manifestFileName: string | null;
  onManifestFileNameChange: (name: string | null) => void;
  manifestContent: string;
  onManifestContentChange: (content: string) => void;
  onIngest: () => void;
}

export const IngestManifestModal: React.FC<IngestManifestModalProps> = ({
  isOpen,
  onClose,
  manifestFileName,
  onManifestFileNameChange,
  manifestContent,
  onManifestContentChange,
  onIngest,
}) => {
  if (!isOpen) return null;

  return createPortal(
    <div className="fixed inset-0 z-[9999] w-screen h-screen flex items-center justify-center bg-black/60 p-4 animate-fadeIn overflow-y-auto">
      <div className="bg-white dark:bg-[#111827] rounded-2xl max-w-lg w-full shadow-2xl border border-gray-100 dark:border-gray-800 overflow-hidden">
        {/* Modal Header */}
        <div className="px-6 py-5 border-b border-gray-100 dark:border-gray-800 flex items-center justify-between">
          <div className="flex items-center gap-3.5">
            <div className="w-10 h-10 rounded-xl bg-blue-50 dark:bg-blue-950/60 text-blue-600 dark:text-blue-400 flex items-center justify-center border border-blue-100 dark:border-blue-900/60 shadow-xs shrink-0">
              <FileCode className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-bold text-gray-900 dark:text-white tracking-tight">
                Ingest Software Manifest
              </h3>
              <p className="text-xs text-gray-500 dark:text-gray-400 mt-0.5">
                Extract package coordinates, lockfiles, and dependency relationships
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
        <div className="p-6 space-y-5">
          {/* File Dropzone */}
          <div>
            <label className="block text-xs font-bold uppercase tracking-wider text-gray-700 dark:text-gray-300 mb-2">
              Upload Manifest File
            </label>
            <div className="border-2 border-dashed border-blue-200/90 dark:border-blue-900/60 hover:border-blue-500 dark:hover:border-blue-400 rounded-2xl p-6 text-center bg-gradient-to-b from-blue-50/30 to-slate-50/50 dark:from-blue-950/20 dark:to-slate-900/20 transition-all group">
              <div className="w-11 h-11 rounded-xl bg-blue-100/80 dark:bg-blue-900/40 text-blue-600 dark:text-blue-400 flex items-center justify-center mx-auto mb-2.5 group-hover:scale-105 transition-transform shadow-2xs">
                <Upload className="w-5 h-5" />
              </div>
              {manifestFileName ? (
                <span className="inline-flex items-center gap-1.5 px-3 py-1 bg-emerald-50 dark:bg-emerald-950/50 border border-emerald-200 dark:border-emerald-800 rounded-full text-xs font-semibold text-emerald-700 dark:text-emerald-300">
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  <span>{manifestFileName}</span>
                </span>
              ) : (
                <div>
                  <p className="text-xs font-semibold text-gray-800 dark:text-gray-200">
                    Drag and drop package manifest, or{' '}
                    <label
                      htmlFor="manifest-file"
                      className="text-blue-600 dark:text-blue-400 hover:underline cursor-pointer"
                    >
                      browse file
                    </label>
                  </p>
                  <p className="text-[11px] text-gray-400 dark:text-gray-500 mt-1">
                    package.json, pom.xml, requirements.txt, Cargo.toml, go.mod
                  </p>
                </div>
              )}
              <input
                type="file"
                id="manifest-file"
                className="hidden"
                onChange={(e) => {
                  if (e.target.files && e.target.files[0]) {
                    onManifestFileNameChange(e.target.files[0].name);
                  }
                }}
              />
              {!manifestFileName && (
                <label
                  htmlFor="manifest-file"
                  className="mt-3 inline-block px-3.5 py-1.5 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg text-xs font-semibold text-gray-700 dark:text-gray-300 hover:bg-gray-50 cursor-pointer shadow-2xs transition-colors"
                >
                  Choose Manifest
                </label>
              )}
            </div>
          </div>

          {/* Paste textarea */}
          <div>
            <label className="block text-xs font-bold uppercase tracking-wider text-gray-700 dark:text-gray-300 mb-2">
              Or Paste Raw Manifest Content
            </label>
            <textarea
              rows={4}
              value={manifestContent}
              onChange={(e) => onManifestContentChange(e.target.value)}
              placeholder='{\n  "dependencies": {\n    "axios": "^1.7.4"\n  }\n}'
              className="w-full text-xs font-mono p-3 bg-gray-50/70 dark:bg-gray-800/80 border border-gray-200 dark:border-gray-700 rounded-xl text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 transition-all resize-none shadow-2xs"
            />
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
            onClick={onIngest}
            className="px-5 py-2 text-xs font-bold text-white bg-gradient-to-r from-blue-600 to-blue-700 hover:from-blue-700 hover:to-blue-800 rounded-xl shadow-md shadow-blue-500/20 flex items-center gap-2 cursor-pointer transition-all"
          >
            <CheckCircle2 className="w-3.5 h-3.5" />
            <span>Ingest & Parse</span>
          </button>
        </div>
      </div>
    </div>,
    document.body
  );
};
