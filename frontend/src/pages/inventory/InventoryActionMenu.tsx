import React, { useState, useRef, useEffect } from 'react';
import { createPortal } from 'react-dom';
import { MoreVertical, History } from 'lucide-react';

export interface InventoryActionMenuProps {
  componentId: string;
  componentName: string;
  componentVersion: string;
  onOpenHistory: (packageName: string) => void;
  onDelete?: (target: { id: string; name: string; version: string }) => void;
}

export const InventoryActionMenu: React.FC<InventoryActionMenuProps> = ({
  componentId,
  componentName,
  componentVersion,
  onOpenHistory,
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
    const openUpwards = spaceBelow < 220 && rect.top > 220;

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

  const handleHistory = (e: React.MouseEvent) => {
    e.stopPropagation();
    setIsOpen(false);
    onOpenHistory(componentName);
  };


  return (
    <div className="relative inline-block text-left" data-component-id={componentId}>
      {/* 3 Dots Trigger Button */}
      <button
        ref={buttonRef}
        type="button"
        onClick={handleToggle}
        title="More actions"
        aria-label="Component actions"
        aria-expanded={isOpen}
        className={`p-1.5 rounded-lg border transition-all cursor-pointer shadow-2xs flex items-center justify-center ${isOpen
          ? 'bg-blue-50 dark:bg-blue-950/60 text-blue-600 dark:text-blue-400 border-blue-300 dark:border-blue-600 ring-2 ring-blue-500/20'
          : 'bg-white dark:bg-gray-800 text-gray-500 dark:text-gray-400 border-gray-200 dark:border-gray-700 hover:text-gray-900 dark:hover:text-white hover:bg-gray-50 dark:hover:bg-gray-700 hover:border-gray-300 dark:hover:border-gray-600'
          }`}
      >
        <MoreVertical className="w-3.5 h-3.5" />
      </button>

      {/* Floating Dropdown Portal */}
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
            }}
            className="z-50 w-56 bg-white dark:bg-[#111827] border border-gray-200 dark:border-gray-700/80 rounded-xl shadow-2xl p-1.5 animate-fadeIn backdrop-blur-md text-left select-none"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Header info */}
            <div className="px-3 py-1.5 border-b border-gray-100 dark:border-gray-800/80 mb-1">
              <span className="text-[10px] font-bold uppercase tracking-wider text-gray-400 dark:text-gray-500">
                Component Actions
              </span>
              <p
                className="text-xs font-semibold text-gray-900 dark:text-white truncate font-mono mt-0.5"
                title={`${componentName}@${componentVersion}`}
              >
                {componentName} <span className="text-gray-400 font-normal">v{componentVersion}</span>
              </p>
            </div>

            {/* Option 1: Audit History */}
            <button
              type="button"
              onClick={handleHistory}
              className="w-full text-left px-2.5 py-2 text-xs font-semibold rounded-lg text-gray-700 dark:text-gray-200 hover:bg-blue-50 dark:hover:bg-blue-950/50 hover:text-blue-600 dark:hover:text-blue-400 flex items-center gap-2.5 transition-colors cursor-pointer group"
            >
              <div className="w-7 h-7 rounded-lg bg-blue-100/70 dark:bg-blue-900/50 text-blue-600 dark:text-blue-400 flex items-center justify-center shrink-0 group-hover:scale-105 transition-transform">
                <History className="w-3.5 h-3.5" />
              </div>
              <div className="flex-1 min-w-0">
                <div className="font-bold text-gray-900 dark:text-white group-hover:text-blue-600 dark:group-hover:text-blue-400">
                  Audit History
                </div>
                <div className="text-[10px] text-gray-500 dark:text-gray-400 truncate">
                  View version & audit timeline
                </div>
              </div>
            </button>
          </div>,
          document.body
        )}
    </div>
  );
};
