import React from 'react';
import { Calendar, Clock, Play, PlusCircle, Trash2, X } from 'lucide-react';

export interface ScanScheduleItem {
  id: string;
  name: string;
  project: string;
  frequency: string;
  days: string;
  nextRun: string;
  lastRun: string;
  enabled: boolean;
}

interface ScanSchedulesTabProps {
  schedulesList: ScanScheduleItem[];
  onToggleSchedule: (id: string) => void;
  onRunNow: (sched: ScanScheduleItem) => void;
  onDeleteSchedule: (id: string) => void;
  onOpenCreateModal: () => void;
}

export const ScanSchedulesTab: React.FC<ScanSchedulesTabProps> = ({
  schedulesList,
  onToggleSchedule,
  onRunNow,
  onDeleteSchedule,
  onOpenCreateModal,
}) => {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-end">
        <button
          type="button"
          onClick={onOpenCreateModal}
          className="px-3.5 py-2 text-xs font-semibold bg-blue-600 hover:bg-blue-700 text-white rounded-lg shadow-2xs inline-flex items-center gap-2 cursor-pointer transition-colors shrink-0"
        >
          <PlusCircle className="w-4 h-4" />
          <span>Create Schedule</span>
        </button>
      </div>

      {schedulesList.length === 0 ? (
        <div className="bg-white dark:bg-[#111827] border border-gray-200 dark:border-gray-800 rounded-2xl p-12 text-center">
          <div className="flex flex-col items-center justify-center max-w-md mx-auto space-y-3">
            <div className="w-12 h-12 rounded-full bg-blue-50 dark:bg-blue-950/50 flex items-center justify-center text-blue-500 border border-blue-200 dark:border-blue-800">
              <Calendar className="w-6 h-6" />
            </div>
            <div>
              <h3 className="text-base font-bold text-gray-900 dark:text-white">No Scheduled Scans Yet</h3>
              <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                Static placeholder data has been removed. Configure your first real recurring scan schedule below to automate security audits.
              </p>
            </div>
            <button
              type="button"
              onClick={onOpenCreateModal}
              className="px-4 py-2 text-xs font-bold bg-blue-600 hover:bg-blue-700 text-white rounded-lg shadow-sm inline-flex items-center gap-2 cursor-pointer transition-colors mt-2"
            >
              <PlusCircle className="w-4 h-4" />
              <span>Create Scan Schedule</span>
            </button>
          </div>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {schedulesList.map((sched) => (
            <div
              key={sched.id}
              className="bg-white dark:bg-[#111827] border border-gray-200 dark:border-gray-800 rounded-xl p-5 shadow-2xs flex flex-col justify-between space-y-4"
            >
              <div>
                <div className="flex items-start justify-between gap-2">
                  <div className="w-8 h-8 rounded-lg bg-orange-50 dark:bg-orange-950/60 text-orange-600 flex items-center justify-center shrink-0">
                    <Calendar className="w-4 h-4" />
                  </div>
                  <label className="flex items-center gap-1.5 text-xs text-gray-500 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={sched.enabled}
                      onChange={() => onToggleSchedule(sched.id)}
                      className="rounded text-blue-600 focus:ring-blue-500"
                    />
                    <span>{sched.enabled ? 'Enabled' : 'Disabled'}</span>
                  </label>
                </div>

                <h3 className="text-sm font-bold text-gray-900 dark:text-white mt-3">
                  {sched.name}
                </h3>
                <p className="text-xs font-semibold text-blue-600 dark:text-blue-400 mt-0.5">
                  {sched.project}
                </p>

                <div className="mt-3 space-y-1.5 text-xs text-gray-600 dark:text-gray-400 bg-gray-50 dark:bg-gray-800/40 p-2.5 rounded-lg border border-gray-100 dark:border-gray-700/60">
                  <div className="flex justify-between">
                    <span className="text-gray-400">Cadence:</span>
                    <span className="font-semibold text-gray-800 dark:text-gray-200">{sched.frequency}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">Next Run:</span>
                    <span className="text-emerald-600 font-semibold">{sched.nextRun}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">Last Run:</span>
                    <span>{sched.lastRun}</span>
                  </div>
                </div>
              </div>

              <div className="flex items-center justify-between pt-3 border-t border-gray-100 dark:border-gray-800 text-xs">
                <button
                  onClick={() => onRunNow(sched)}
                  className="font-bold text-blue-600 dark:text-blue-400 hover:underline flex items-center gap-1 cursor-pointer"
                >
                  <Play className="w-3.5 h-3.5" />
                  Run Now
                </button>

                <button
                  onClick={() => onDeleteSchedule(sched.id)}
                  className="text-gray-400 hover:text-red-600 cursor-pointer p-1"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

interface CreateScheduleModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSubmit: (e: React.FormEvent) => void;
  newSchedName: string;
  onNewSchedNameChange: (val: string) => void;
  newSchedProject: string;
  onNewSchedProjectChange: (val: string) => void;
  newSchedDate: string;
  onNewSchedDateChange: (val: string) => void;
  newSchedTime: string;
  onNewSchedTimeChange: (val: string) => void;
  newSchedTimezone: string;
  onNewSchedTimezoneChange: (val: string) => void;
  newSchedFreq: string;
  onNewSchedFreqChange: (val: string) => void;
}

export const CreateScheduleModal: React.FC<CreateScheduleModalProps> = ({
  isOpen,
  onClose,
  onSubmit,
  newSchedName,
  onNewSchedNameChange,
  newSchedProject,
  onNewSchedProjectChange,
  newSchedDate,
  onNewSchedDateChange,
  newSchedTime,
  onNewSchedTimeChange,
  newSchedTimezone,
  onNewSchedTimezoneChange,
  newSchedFreq,
  onNewSchedFreqChange,
}) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4 animate-fadeIn backdrop-blur-xs">
      <div className="bg-white dark:bg-[#111827] rounded-xl max-w-lg w-full p-6 shadow-2xl border border-gray-200 dark:border-gray-800 space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-gray-100 dark:border-gray-800">
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-lg bg-blue-50 dark:bg-blue-950/60 text-blue-600 flex items-center justify-center">
              <Calendar className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-base font-bold text-gray-900 dark:text-white">Create Scan Schedule</h3>
              <p className="text-[11px] text-gray-500 dark:text-gray-400">Configure recurring automated SBOM security audits</p>
            </div>
          </div>
          <button onClick={onClose} className="p-1 text-gray-400 hover:text-gray-600 rounded-lg">
            <X className="w-5 h-5" />
          </button>
        </div>

        <form onSubmit={onSubmit} className="space-y-3.5 text-xs">
          <div>
            <label className="block font-semibold text-gray-700 dark:text-gray-300 mb-1">Schedule Name</label>
            <input
              type="text"
              required
              value={newSchedName}
              onChange={(e) => onNewSchedNameChange(e.target.value)}
              placeholder="e.g. Nightly Core Scan"
              className="w-full px-3 py-2 border border-gray-200 dark:border-gray-700 rounded-lg bg-gray-50 dark:bg-gray-800 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500/20"
            />
          </div>

          <div>
            <label className="block font-semibold text-gray-700 dark:text-gray-300 mb-1">Target Project</label>
            <select
              value={newSchedProject}
              onChange={(e) => onNewSchedProjectChange(e.target.value)}
              className="w-full px-3 py-2 border border-gray-200 dark:border-gray-700 rounded-lg bg-gray-50 dark:bg-gray-800 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500/20"
            >
              <option value="Payments API">Payments API</option>
              <option value="Customer Portal">Customer Portal</option>
              <option value="Checkout Service">Checkout Service</option>
              <option value="Mobile App Backend">Mobile App Backend</option>
              <option value="Admin Portal">Admin Portal</option>
            </select>
          </div>

          <div className="p-3.5 bg-gray-50 dark:bg-gray-800/50 rounded-xl border border-gray-200 dark:border-gray-700/80 space-y-3">
            <div className="flex items-center justify-between">
              <span className="font-bold text-gray-800 dark:text-gray-200 flex items-center gap-1.5 text-xs">
                <Calendar className="w-3.5 h-3.5 text-blue-500" />
                Select Date & Time (Calendar)
              </span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
              <div>
                <label className="block text-[11px] font-semibold text-gray-600 dark:text-gray-400 mb-1">
                  Execution Date
                </label>
                <input
                  type="date"
                  required
                  value={newSchedDate}
                  onChange={(e) => onNewSchedDateChange(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-200 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-white font-medium text-xs focus:outline-none focus:ring-2 focus:ring-blue-500/20 cursor-pointer"
                />
              </div>

              <div>
                <label className="block text-[11px] font-semibold text-gray-600 dark:text-gray-400 mb-1">
                  Execution Time
                </label>
                <div className="grid grid-cols-2 gap-1.5">
                  <input
                    type="time"
                    required
                    value={newSchedTime}
                    onChange={(e) => onNewSchedTimeChange(e.target.value)}
                    className="w-full px-2.5 py-2 border border-gray-200 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-white font-medium text-xs focus:outline-none focus:ring-2 focus:ring-blue-500/20 cursor-pointer font-mono"
                  />
                  <select
                    value={newSchedTimezone}
                    onChange={(e) => onNewSchedTimezoneChange(e.target.value)}
                    className="w-full px-2 py-2 border border-gray-200 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-white font-medium text-xs focus:outline-none focus:ring-2 focus:ring-blue-500/20 cursor-pointer"
                  >
                    <option value="UTC">UTC</option>
                    <option value="EST">EST</option>
                    <option value="PST">PST</option>
                    <option value="IST">IST</option>
                    <option value="CET">CET</option>
                  </select>
                </div>
              </div>
            </div>

            <div className="flex items-center gap-1.5 pt-0.5 flex-wrap">
              <span className="text-[10px] text-gray-400 font-bold uppercase">Quick Dates:</span>
              <button
                type="button"
                onClick={() => onNewSchedDateChange(new Date().toISOString().split('T')[0])}
                className="px-2 py-0.5 rounded text-[10px] bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 hover:border-blue-400 text-gray-600 dark:text-gray-300 transition-colors cursor-pointer shadow-2xs"
              >
                Today
              </button>
              <button
                type="button"
                onClick={() => {
                  const tom = new Date();
                  tom.setDate(tom.getDate() + 1);
                  onNewSchedDateChange(tom.toISOString().split('T')[0]);
                }}
                className="px-2 py-0.5 rounded text-[10px] bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 hover:border-blue-400 text-gray-600 dark:text-gray-300 transition-colors cursor-pointer shadow-2xs"
              >
                Tomorrow
              </button>
              <button
                type="button"
                onClick={() => {
                  const nextWk = new Date();
                  nextWk.setDate(nextWk.getDate() + 7);
                  onNewSchedDateChange(nextWk.toISOString().split('T')[0]);
                }}
                className="px-2 py-0.5 rounded text-[10px] bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 hover:border-blue-400 text-gray-600 dark:text-gray-300 transition-colors cursor-pointer shadow-2xs"
              >
                +7 Days
              </button>
              <button
                type="button"
                onClick={() => {
                  const firstNextMo = new Date();
                  firstNextMo.setMonth(firstNextMo.getMonth() + 1, 1);
                  onNewSchedDateChange(firstNextMo.toISOString().split('T')[0]);
                }}
                className="px-2 py-0.5 rounded text-[10px] bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 hover:border-blue-400 text-gray-600 dark:text-gray-300 transition-colors cursor-pointer shadow-2xs"
              >
                1st of Next Month
              </button>
            </div>
          </div>

          <div>
            <label className="block font-semibold text-gray-700 dark:text-gray-300 mb-1">Recurrence Frequency</label>
            <select
              value={newSchedFreq}
              onChange={(e) => onNewSchedFreqChange(e.target.value)}
              className="w-full px-3 py-2 border border-gray-200 dark:border-gray-700 rounded-lg bg-gray-50 dark:bg-gray-800 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500/20 cursor-pointer"
            >
              <option value="Daily">Daily</option>
              <option value="Weekly on Sunday">Weekly on Sunday</option>
              <option value="Weekly on Monday">Weekly on Monday</option>
              <option value="Monthly (1st of month)">Monthly (1st of month)</option>
              <option value="One-time Run">One-time Run (No recurrence)</option>
            </select>
          </div>

          <div className="p-2.5 bg-blue-50/70 dark:bg-blue-950/30 border border-blue-200/60 dark:border-blue-900/40 rounded-lg flex items-center justify-between text-[11px]">
            <div className="flex items-center gap-1.5 text-blue-800 dark:text-blue-300">
              <Clock className="w-3.5 h-3.5 text-blue-600 shrink-0" />
              <span>Next scheduled run:</span>
            </div>
            <span className="font-bold text-blue-900 dark:text-blue-200 font-mono">
              {newSchedDate || 'Selected Date'} @ {newSchedTime} {newSchedTimezone}
            </span>
          </div>

          <div className="flex justify-end gap-2 pt-3 border-t border-gray-100 dark:border-gray-800">
            <button
              type="button"
              onClick={onClose}
              className="px-3.5 py-1.5 border border-gray-200 dark:border-gray-700 rounded-lg text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors cursor-pointer"
            >
              Cancel
            </button>
            <button
              type="submit"
              className="px-4 py-1.5 bg-blue-600 hover:bg-blue-700 text-white font-bold rounded-lg shadow-sm transition-colors cursor-pointer flex items-center gap-1.5"
            >
              <Calendar className="w-3.5 h-3.5" />
              <span>Create Schedule</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
