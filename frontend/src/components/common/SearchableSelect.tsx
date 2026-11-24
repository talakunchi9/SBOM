import React, { useEffect, useId, useMemo, useRef, useState } from 'react';
import { Check, ChevronDown, Loader2, Plus, Search, X } from 'lucide-react';
import type { CatalogRecord } from '../../api/client';

export type SearchableSelectOption = CatalogRecord;

interface SearchableSelectProps {
  label: React.ReactNode;
  value: SearchableSelectOption | null;
  options: SearchableSelectOption[];
  onChange: (option: SearchableSelectOption | null) => void;
  onQueryChange?: (query: string) => void;
  onOpen?: () => void;
  onLoadMore?: () => void;
  onCreate?: (name: string) => Promise<void> | void;
  allowCreate?: boolean;
  freeform?: boolean;
  creating?: boolean;
  loading?: boolean;
  disabled?: boolean;
  required?: boolean;
  placeholder?: string;
  disabledPlaceholder?: string;
  emptyMessage?: string;
  error?: string | null;
  hint?: string;
  variant?: 'scan' | 'form';
  hasMore?: boolean;
}

const INPUT = {
  scan: 'w-full text-xs px-3 py-2 pr-8 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg text-gray-900 dark:text-white focus:ring-1 focus:ring-blue-500 disabled:bg-gray-50 dark:disabled:bg-gray-900 disabled:text-gray-400',
  form: 'w-full px-2.5 py-1.5 pr-8 text-xs bg-gray-50/70 dark:bg-gray-800/80 border border-gray-200 dark:border-gray-700 rounded-lg text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 disabled:bg-gray-50 dark:disabled:bg-gray-900 disabled:text-gray-400 shadow-2xs',
};

const LABEL = {
  scan: 'block text-xs font-semibold text-gray-700 dark:text-gray-300 mb-1',
  form: 'block text-[11px] font-bold text-gray-700 dark:text-gray-300 uppercase tracking-tight mb-1',
};

export const SearchableSelect: React.FC<SearchableSelectProps> = ({
  label,
  value,
  options,
  onChange,
  onQueryChange,
  onOpen,
  onLoadMore,
  onCreate,
  allowCreate = false,
  freeform = false,
  creating = false,
  loading = false,
  disabled = false,
  required = false,
  placeholder = 'Select…',
  disabledPlaceholder,
  emptyMessage = 'No results found',
  error,
  hint,
  variant = 'form',
  hasMore = false,
}) => {
  const listId = useId();
  const rootRef = useRef<HTMLDivElement>(null);
  const listRef = useRef<HTMLDivElement>(null);
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const display = value?.name ?? '';
  const shownPlaceholder = disabled && disabledPlaceholder ? disabledPlaceholder : placeholder;
  const trimmed = display.trim();
  const exactMatch = options.some((option) => option.name.toLowerCase() === trimmed.toLowerCase());
  const canCreate = Boolean(allowCreate && onCreate && trimmed && !exactMatch);
  const visible = useMemo(() => {
    if (!trimmed) return options;
    const lower = trimmed.toLowerCase();
    return options.filter((opt) => opt.name.toLowerCase().includes(lower));
  }, [options, trimmed]);
  const itemCount = visible.length + (canCreate ? 1 : 0);

  useEffect(() => {
    setActive(0);
  }, [trimmed, canCreate]);

  useEffect(() => {
    const onDoc = (event: MouseEvent) => {
      if (!rootRef.current?.contains(event.target as Node)) {
        setOpen(false);
      }
    };
    document.addEventListener('mousedown', onDoc);
    return () => document.removeEventListener('mousedown', onDoc);
  }, []);

  const select = (option: SearchableSelectOption | null) => {
    onChange(option);
    setOpen(false);
  };

  const commitCreate = async () => {
    if (!canCreate || creating) return;
    try {
      await onCreate?.(trimmed);
      setOpen(false);
    } catch {
      // Field-level error is shown by the parent.
    }
  };

  const activate = (index: number) => {
    if (canCreate && index === 0) {
      void commitCreate();
      return;
    }
    const option = visible[canCreate ? index - 1 : index];
    if (option) select(option);
  };

  const openList = () => {
    if (disabled) return;
    setOpen(true);
    onQueryChange?.(display);
    onOpen?.();
  };

  const onScroll = () => {
    const node = listRef.current;
    if (!node || !hasMore || loading) return;
    if (node.scrollTop + node.clientHeight >= node.scrollHeight - 24) onLoadMore?.();
  };

  return (
    <div ref={rootRef} className="relative">
      <label className={LABEL[variant]}>
        {label}
        {required && <span className="text-red-500"> *</span>}
      </label>
      <div className="relative">
        <Search className="w-3.5 h-3.5 text-gray-400 absolute left-2.5 top-1/2 -translate-y-1/2 pointer-events-none" />
        <input
          type="text"
          role="combobox"
          aria-expanded={open}
          aria-controls={listId}
          aria-autocomplete="list"
          aria-required={required}
          aria-disabled={disabled}
          disabled={disabled}
          value={display}
          placeholder={shownPlaceholder}
          onFocus={openList}
          onClick={openList}
          onChange={(event) => {
            const next = event.target.value;
            setOpen(true);
            onQueryChange?.(next);
            if (freeform) {
              const trimmedNext = next.trim();
              if (!trimmedNext) {
                onChange(null);
              } else {
                const match = options.find((opt) => opt.name.toLowerCase() === trimmedNext.toLowerCase());
                onChange(match || { id: '', name: next });
              }
            } else {
              if (value && next.trim() !== '' && next !== value.name) onChange(null);
            }
          }}
          onKeyDown={(event) => {
            if (disabled) return;
            if (event.key === 'ArrowDown') {
              event.preventDefault();
              if (!open) openList();
              setActive((index) => Math.min(index + 1, Math.max(itemCount - 1, 0)));
            } else if (event.key === 'ArrowUp') {
              event.preventDefault();
              setActive((index) => Math.max(index - 1, 0));
            } else if (event.key === 'Enter') {
              if (open && visible.length > 0 && active >= 0 && active < visible.length) {
                event.preventDefault();
                activate(active);
              } else {
                setOpen(false);
              }
            } else if (event.key === 'Escape') {
              setOpen(false);
            }
          }}
          className={`${INPUT[variant]} pl-8`}
        />
        {value && !disabled ? (
          <button
            type="button"
            className="absolute right-7 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600"
            onClick={() => select(null)}
            aria-label="Clear selection"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        ) : null}
        <span className="absolute right-2.5 top-1/2 -translate-y-1/2 text-gray-400 pointer-events-none">
          {loading || creating ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <ChevronDown className="w-3.5 h-3.5" />}
        </span>
      </div>
      {open && !disabled && (visible.length > 0 || canCreate) && (
        <div
          id={listId}
          role="listbox"
          ref={listRef}
          onScroll={onScroll}
          className="absolute z-50 mt-1 w-full max-h-52 overflow-auto rounded-lg border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900 shadow-lg"
        >
          {canCreate ? (
            <button
              type="button"
              role="option"
              aria-selected={active === 0}
              className={`w-full flex items-center gap-2 px-3 py-2 text-left text-xs font-semibold text-blue-700 dark:text-blue-300 ${
                active === 0 ? 'bg-blue-50 dark:bg-blue-950/40' : ''
              }`}
              onMouseEnter={() => setActive(0)}
              onMouseDown={(e) => {
                e.preventDefault();
                void commitCreate();
              }}
            >
              {creating ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Plus className="w-3.5 h-3.5" />}
              <span>Add “{trimmed}”</span>
            </button>
          ) : null}
          {visible.map((option, index) => {
            const rowIndex = index + (canCreate ? 1 : 0);
            const selected = Boolean(value?.id === option.id || (value?.name && value.name.toLowerCase() === option.name.toLowerCase()));
            return (
              <button
                type="button"
                key={option.id}
                role="option"
                aria-selected={selected}
                className={`w-full flex items-center justify-between px-3 py-2 text-left text-xs ${
                  rowIndex === active ? 'bg-blue-50 dark:bg-blue-950/40' : ''
                } ${selected ? 'text-blue-700 dark:text-blue-300 font-semibold' : 'text-gray-800 dark:text-gray-100'}`}
                onMouseEnter={() => setActive(rowIndex)}
                onMouseDown={(e) => {
                  e.preventDefault();
                  select(option);
                }}
              >
                <span>{option.name}</span>
                {selected ? <Check className="w-3.5 h-3.5" /> : null}
              </button>
            );
          })}
        </div>
      )}
      {error && !open ? <p className="text-[10px] text-red-500 mt-1">{error}</p> : null}
      {hint ? <p className="text-[10px] text-gray-400 mt-1">{hint}</p> : null}
    </div>
  );
};
