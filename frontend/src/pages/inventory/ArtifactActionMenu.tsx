import React, { useState, useRef, useEffect } from 'react';
import { createPortal } from 'react-dom';
import { MoreVertical, Eye, Download } from 'lucide-react';

export interface SbomArtifactItem {
  id: string;
  scanId: string;
  snapshotId?: string;
  fileName: string;
  fileSize: string;
  format: 'SPDX-2.3' | 'CycloneDX-1.5';
  project: string;
  module: string;
  components: number;
  signed: 'Pass' | 'Fail';
  uploaded: string;
  isFailingRow?: boolean;
}

export interface ArtifactActionMenuProps {
  artifact: SbomArtifactItem;
  onViewDetails: (artifact: SbomArtifactItem) => void;
  onDownload: (artifact: SbomArtifactItem) => void;
}

export const ArtifactActionMenu: React.FC<ArtifactActionMenuProps> = ({
  artifact,
  onViewDetails,
  onDownload,
}) => {
  const [isOpen, setIsOpen] = useState(false);
  const [menuCoords, setMenuCoords] = useState<{
    top?: number;
    bottom?: number;
    right: number;
  } | null>(null);

  const buttonRef = useRef<HTMLButtonElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);

  const updatePosition = () => {
    if (!buttonRef.current) return;
    const rect = buttonRef.current.getBoundingClientRect();
    const spaceBelow = window.innerHeight - rect.bottom;
    const openUpwards = spaceBelow < 180 && rect.top > 180;

    setMenuCoords({
      top: openUpwards ? undefined : rect.bottom + 6,
      bottom: openUpwards ? window.innerHeight - rect.top + 6 : undefined,
      right: Math.max(12, window.innerWidth - rect.right),
    });
  };

  const handleToggle = (e: React.MouseEvent) => {
    e.stopPropagation();
    if (!isOpen) {
      updatePosition();
      setIsOpen(true);
    } else {
      setIsOpen(false);
    }
  };

  useEffect(() => {
    if (!isOpen) return;
    updatePosition();

    const handlePointerDown = (e: MouseEvent | TouchEvent) => {
      const target = e.target as Node;
      if (
        menuRef.current &&
        !menuRef.current.contains(target) &&
        buttonRef.current &&
        !buttonRef.current.contains(target)
      ) {
        setIsOpen(false);
      }
    };

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setIsOpen(false);
      }
    };

    const handleScroll = (e: Event) => {
      const target = e.target as Node;
      if (menuRef.current && menuRef.current.contains(target)) return;
      setIsOpen(false);
    };

    window.addEventListener('scroll', handleScroll, true);
    window.addEventListener('resize', updatePosition);
    document.addEventListener('mousedown', handlePointerDown);
    document.addEventListener('touchstart', handlePointerDown);
    document.addEventListener('keydown', handleKeyDown);

    return () => {
      window.removeEventListener('scroll', handleScroll, true);
      window.removeEventListener('resize', updatePosition);
      document.removeEventListener('mousedown', handlePointerDown);
      document.removeEventListener('touchstart', handlePointerDown);
      document.removeEventListener('keydown', handleKeyDown);
    };
  }, [isOpen]);

  const handleView = (e: React.MouseEvent) => {
    e.stopPropagation();
    setIsOpen(false);
    onViewDetails(artifact);
  };

  const handleDl = (e: React.MouseEvent) => {
    e.stopPropagation();
    setIsOpen(false);
    onDownload(artifact);
  };

  return (
    <>
      <button
        ref={buttonRef}
        type="button"
        onClick={handleToggle}
        className={`p-1.5 rounded-lg border transition-all cursor-pointer ${
          isOpen
            ? 'bg-blue-50 border-blue-300 text-blue-600 dark:bg-blue-950/50 dark:border-blue-700 dark:text-blue-400'
            : 'border-transparent text-gray-400 hover:text-gray-700 dark:hover:text-gray-200 hover:bg-gray-100 dark:hover:bg-gray-800'
        }`}
        title={`Actions for ${artifact.fileName}`}
        aria-label={`Actions for ${artifact.fileName}`}
        aria-expanded={isOpen}
      >
        <MoreVertical className="w-4 h-4" />
      </button>

      {isOpen &&
        menuCoords &&
        createPortal(
          <div
            ref={menuRef}
            style={{
              position: 'fixed',
              top: menuCoords.top !== undefined ? `${menuCoords.top}px` : undefined,
              bottom: menuCoords.bottom !== undefined ? `${menuCoords.bottom}px` : undefined,
              right: `${menuCoords.right}px`,
              zIndex: 99999,
            }}
            className="w-48 bg-white dark:bg-gray-900 rounded-xl shadow-xl border border-gray-200/90 dark:border-gray-800 p-1.5 text-xs animate-in fade-in zoom-in-95 duration-100 select-none"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="px-2 py-1 text-[10px] font-bold uppercase tracking-wider text-gray-400 dark:text-gray-500 border-b border-gray-100 dark:border-gray-800 mb-1 truncate">
              {artifact.fileName}
            </div>

            {/* Option 1: View Details */}
            <button
              type="button"
              onClick={handleView}
              className="w-full text-left px-2.5 py-2 text-xs rounded-lg text-gray-700 dark:text-gray-200 hover:bg-blue-50 dark:hover:bg-blue-950/40 hover:text-blue-600 dark:hover:text-blue-400 flex items-center gap-2.5 transition-colors cursor-pointer group"
            >
              <div className="w-6 h-6 rounded bg-blue-50 dark:bg-blue-900/40 text-blue-600 dark:text-blue-400 flex items-center justify-center shrink-0 group-hover:scale-105 transition-transform">
                <Eye className="w-3.5 h-3.5" />
              </div>
              <div className="flex-1 min-w-0">
                <div className="font-semibold text-gray-900 dark:text-white group-hover:text-blue-600 dark:group-hover:text-blue-400 text-xs">
                  View Details
                </div>
                <div className="text-[10px] text-gray-400 dark:text-gray-500 truncate">
                  Inspect metadata & spec
                </div>
              </div>
            </button>

            {/* Option 2: Download */}
            <button
              type="button"
              onClick={handleDl}
              className="w-full text-left px-2.5 py-2 text-xs rounded-lg text-gray-700 dark:text-gray-200 hover:bg-emerald-50 dark:hover:bg-emerald-950/40 hover:text-emerald-600 dark:hover:text-emerald-400 flex items-center gap-2.5 transition-colors cursor-pointer group mt-0.5"
            >
              <div className="w-6 h-6 rounded bg-emerald-50 dark:bg-emerald-900/40 text-emerald-600 dark:text-emerald-400 flex items-center justify-center shrink-0 group-hover:scale-105 transition-transform">
                <Download className="w-3.5 h-3.5" />
              </div>
              <div className="flex-1 min-w-0">
                <div className="font-semibold text-gray-900 dark:text-white group-hover:text-emerald-600 dark:group-hover:text-emerald-400 text-xs">
                  Download
                </div>
                <div className="text-[10px] text-gray-400 dark:text-gray-500 truncate">
                  Choose output format
                </div>
              </div>
            </button>
          </div>,
          document.body
        )}
    </>
  );
};
