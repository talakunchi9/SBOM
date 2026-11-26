import React from 'react';
import { useNavigate } from 'react-router-dom';
import {
  AlertTriangle,
  ArrowLeft,
  Ban,
  CheckCircle2,
  Clock,
  ExternalLink,
  Radio,
  RotateCcw,
  Shield,
  Terminal,
} from 'lucide-react';
import type { ScanJob, ScanStatus } from '../../../types';
import { displayStatus, formatDuration, formatEventTime, isOpenStatus, stageLabel } from '../scanProgress';
import { PipelineGrid } from '../ScanResultDetails';

interface LiveScanMonitorTabProps {
  waitingScans: ScanJob[];
  activeScan: ScanJob | null;
  pipelineScan: ScanJob | null;
  bulkChildren: ScanJob[];
  scanFailed: boolean;
  now: number;
  cancellingId: string | null;
  rescanningId: string | null;
  canCancel: (status: ScanStatus) => boolean;
  canRescan: (status: ScanStatus) => boolean;
  onGoToLaunchScan: () => void;
  onCancel: (scan: ScanJob) => void;
  onRescan: (scan: ScanJob) => void;
  onSelectScan: (scanId: string) => void;
}

export const LiveScanMonitorTab: React.FC<LiveScanMonitorTabProps> = ({
  waitingScans,
  activeScan,
  pipelineScan,
  bulkChildren,
  scanFailed,
  now,
  cancellingId,
  rescanningId,
  canCancel,
  canRescan,
  onGoToLaunchScan,
  onCancel,
  onRescan,
  onSelectScan,
}) => {
  const navigate = useNavigate();

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between pb-1">
        <button
          type="button"
          onClick={onGoToLaunchScan}
          className="inline-flex items-center gap-1.5 text-xs font-semibold text-gray-600 dark:text-gray-400 hover:text-blue-600 dark:hover:text-blue-400 cursor-pointer transition-colors"
          title="Back to Launch Scan"
        >
          <ArrowLeft className="w-3.5 h-3.5" />
          <span>Back</span>
        </button>
      </div>

      {waitingScans.length > 0 && (
        <div className="bg-white dark:bg-[#111827] border border-gray-200 dark:border-gray-800 rounded-xl shadow-2xs overflow-hidden">
          <div className="px-5 py-3 border-b border-gray-100 dark:border-gray-800 flex items-center justify-between">
            <h2 className="text-sm font-bold text-gray-900 dark:text-white">Waiting in queue</h2>
            <span className="text-[11px] font-semibold text-amber-700 dark:text-amber-300">
              {waitingScans.length} not started
            </span>
          </div>
          <div className="divide-y divide-gray-100 dark:divide-gray-800">
            {waitingScans.map((scan) => (
              <div key={scan.id} className="px-5 py-3 flex items-center justify-between gap-3">
                <div className="min-w-0">
                  <p className="text-sm font-semibold text-gray-900 dark:text-white truncate">{scan.targetProject}</p>
                  <p className="text-[11px] text-gray-500 truncate">{scan.appService || scan.scanType} · {scan.source}</p>
                </div>
                <button
                  type="button"
                  disabled={cancellingId === scan.id}
                  onClick={() => onCancel(scan)}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-600 bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-200 hover:border-rose-300 hover:text-rose-700 dark:hover:text-rose-300 text-xs font-semibold cursor-pointer disabled:opacity-50 shrink-0"
                >
                  <Ban className="w-3.5 h-3.5" />
                  {cancellingId === scan.id ? 'Stopping' : 'Cancel'}
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {activeScan ? (
        <div className="bg-white dark:bg-[#111827] border border-gray-200 dark:border-gray-800 rounded-xl p-6 shadow-2xs space-y-6">
          {/* Job Summary Banner */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-gray-100 dark:border-gray-800">
            <div className="flex items-center gap-3">
              <div className={`w-10 h-10 rounded-xl flex items-center justify-center ${scanFailed
                ? 'bg-red-50 dark:bg-red-950/40 text-red-600'
                : activeScan.status === 'completed'
                  ? 'bg-emerald-50 dark:bg-emerald-950/40 text-emerald-600'
                  : 'bg-blue-50 dark:bg-blue-950/60 text-blue-600'
                }`}>
                {scanFailed ? <AlertTriangle className="w-5 h-5" /> : activeScan.status === 'completed' ? <CheckCircle2 className="w-5 h-5" /> : <Radio className={`w-5 h-5 ${isOpenStatus(activeScan.status) ? 'animate-pulse' : ''}`} />}
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h2 className="text-base font-bold text-gray-900 dark:text-white">
                    {activeScan.targetProject}
                  </h2>
                  {/* UUID intentionally hidden from UI */}
                  <span className={`px-2 py-0.5 text-[10px] font-bold rounded uppercase ${scanFailed
                    ? 'bg-red-50 text-red-700 dark:bg-red-950/60 dark:text-red-300'
                    : activeScan.status === 'completed'
                      ? 'bg-emerald-50 text-emerald-700 dark:bg-emerald-950/60 dark:text-emerald-300'
                      : activeScan.status === 'cancelled'
                        ? 'bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-300'
                        : 'bg-blue-50 dark:bg-blue-950/60 text-blue-700 dark:text-blue-300'
                    }`}>
                    {displayStatus(activeScan.status)}
                  </span>
                </div>
                <p className="text-xs text-gray-500 dark:text-gray-400 mt-0.5">
                  {activeScan.scanType} • {activeScan.source}
                </p>
              </div>
            </div>

            <div className="flex items-center gap-2 text-xs">
              <div className="flex items-center gap-1.5 text-gray-600 dark:text-gray-400 mr-2">
                <Clock className="w-4 h-4 text-gray-400" />
                <span>{isOpenStatus(activeScan.status) ? (activeScan.startedAt ? 'Elapsed' : 'Queue') : 'Duration'}: <strong className="text-gray-900 dark:text-white font-mono">{activeScan.startedAt ? formatDuration(activeScan.startedAt, isOpenStatus(activeScan.status) ? undefined : activeScan.completedAt, now) : 'Waiting to start'}</strong></span>
              </div>
              <button
                type="button"
                onClick={onGoToLaunchScan}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-600 bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-200 hover:border-blue-400 hover:text-blue-700 dark:hover:text-blue-300 hover:bg-gray-50 dark:hover:bg-slate-800 text-xs font-semibold cursor-pointer transition-colors shadow-2xs"
                title="Back to Launch Scan"
              >
                <ArrowLeft className="w-3.5 h-3.5" />
                Back
              </button>
              {canCancel(activeScan.status) && (
                <button
                  type="button"
                  disabled={cancellingId === activeScan.id}
                  onClick={() => onCancel(activeScan)}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-600 bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-200 hover:border-rose-300 hover:text-rose-700 dark:hover:text-rose-300 text-xs font-semibold cursor-pointer disabled:opacity-50"
                >
                  <Ban className="w-3.5 h-3.5" />
                  {cancellingId === activeScan.id ? 'Stopping' : 'Cancel scan'}
                </button>
              )}
              {canRescan(activeScan.status) && !activeScan.isBulkAggregate && (
                <button
                  type="button"
                  disabled={rescanningId === activeScan.id}
                  onClick={() => onRescan(activeScan)}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-600 bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-200 hover:border-blue-400 hover:text-blue-700 dark:hover:text-blue-300 text-xs font-semibold cursor-pointer disabled:opacity-50"
                >
                  <RotateCcw className={`w-3.5 h-3.5 ${rescanningId === activeScan.id ? 'animate-spin' : ''}`} />
                  {rescanningId === activeScan.id ? 'Queuing' : 'Rescan'}
                </button>
              )}
              {activeScan.status === 'completed' && (
                <button
                  type="button"
                  onClick={() => navigate(`/vulnerabilities?project=${encodeURIComponent(activeScan.targetProject)}`)}
                  className="px-3 py-1.5 bg-rose-600 hover:bg-rose-700 active:bg-rose-800 text-white rounded-lg text-xs font-semibold cursor-pointer shadow-2xs flex items-center gap-1.5 transition-colors"
                  title={`View all findings for ${activeScan.targetProject} in Vulnerability Management`}
                >
                  <Shield className="w-3.5 h-3.5" />
                  <span>View Findings ({activeScan.cvesFound || 0})</span>
                </button>
              )}
              <button
                type="button"
                onClick={() => onSelectScan(activeScan.id)}
                className="px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-xs font-semibold cursor-pointer"
              >
                View results
              </button>
            </div>
          </div>

          {activeScan.errorMessage && (scanFailed || activeScan.status === 'cancelled') && (
            <div className="rounded-lg border border-red-200 dark:border-red-900/50 bg-red-50 dark:bg-red-950/30 px-3 py-2 text-xs text-red-800 dark:text-red-200">
              <span className="font-bold">{activeScan.errorCode || 'Error'}: </span>
              {activeScan.errorMessage}
            </div>
          )}

          <div>
            <div className="flex justify-between text-xs font-semibold mb-1.5">
              <span className="text-gray-700 dark:text-gray-300">
                {activeScan.isBulkAggregate ? 'Batch progress' : stageLabel(activeScan.stage)}
              </span>
              <span className={`font-mono font-bold ${scanFailed ? 'text-red-600' : activeScan.status === 'completed' ? 'text-emerald-600' : 'text-blue-600 dark:text-blue-400'}`}>{activeScan.progress}%</span>
            </div>
            <div className="w-full bg-gray-100 dark:bg-gray-800 rounded-full h-2 overflow-hidden">
              <div
                className={`${scanFailed ? 'bg-red-500' : activeScan.status === 'cancelled' ? 'bg-slate-400' : activeScan.status === 'completed' ? 'bg-emerald-500' : 'bg-blue-600'} h-2 rounded-full transition-all duration-500`}
                style={{ width: `${activeScan.progress}%` }}
              />
            </div>
          </div>

          {activeScan.isBulkAggregate && (
            <div className="overflow-x-auto rounded-xl border border-gray-200 dark:border-gray-800">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="text-gray-500 border-b border-gray-100 dark:border-gray-800">
                    <th className="px-3 py-2 font-semibold">Project</th>
                    <th className="px-3 py-2 font-semibold">Repository</th>
                    <th className="px-3 py-2 font-semibold">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100 dark:divide-gray-800">
                  {(activeScan.bulkItems || []).map((item) => {
                    const child = bulkChildren.find((scan) => scan.id === item.scanId);
                    const status = child?.status || item.status.toLowerCase();
                    return (
                      <tr key={`${item.rowNumber}-${item.scanId || item.repositoryUrl}`}>
                        <td className="px-3 py-2 font-semibold text-gray-900 dark:text-white">{item.projectName || item.applicationName || '—'}</td>
                        <td className="px-3 py-2 font-mono text-gray-500 max-w-[240px] truncate">{item.repositoryUrl}</td>
                        <td className="px-3 py-2">
                          <span className="uppercase font-bold text-[10px]">{displayStatus(status)}</span>
                          {child && (child.status === 'running' || child.status === 'analyzing') && (
                            <span className="text-gray-500"> · {stageLabel(child.stage)} {child.progress}%</span>
                          )}
                          {item.errorMessage && status !== 'completed' && status !== 'running' && status !== 'queued' && status !== 'analyzing' && (
                            <p className="text-[10px] text-red-600 dark:text-red-400 mt-0.5">{item.errorMessage}</p>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}

          {pipelineScan && (
            <div className="space-y-2">
              {activeScan.isBulkAggregate && (
                <p className="text-xs font-semibold text-gray-700 dark:text-gray-300">
                  Current row: {pipelineScan.targetProject} · {stageLabel(pipelineScan.stage)}
                </p>
              )}
              <PipelineGrid job={pipelineScan} />
            </div>
          )}

          {activeScan.status === 'completed' && !activeScan.isBulkAggregate && (
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2 text-xs">
              <div
                onClick={() => {
                  const params = new URLSearchParams({ project: activeScan.targetProject });
                  if (activeScan.id) params.set('scan', activeScan.id);
                  if (activeScan.appService) params.set('app', activeScan.appService);
                  navigate(`/software-inventory?${params.toString()}`);
                }}
                className="rounded-lg border border-gray-200 dark:border-gray-800 px-3 py-2 cursor-pointer hover:border-blue-400 hover:bg-gray-50/70 dark:hover:bg-gray-800/40 transition-all group"
                title={`View ${activeScan.componentsFound} components in Software Inventory`}
              >
                <p className="text-gray-500 flex items-center justify-between">
                  <span>Components</span>
                  <ExternalLink className="w-3 h-3 text-gray-400 opacity-0 group-hover:opacity-100 transition-opacity" />
                </p>
                <p className="text-lg font-bold text-gray-900 dark:text-white">{activeScan.componentsFound}</p>
              </div>
              <div
                onClick={() => {
                  const params = new URLSearchParams({ project: activeScan.targetProject });
                  if (activeScan.id) params.set('scan', activeScan.id);
                  if (activeScan.appService) params.set('app', activeScan.appService);
                  navigate(`/vulnerabilities?${params.toString()}`);
                }}
                className="rounded-lg border border-blue-300 dark:border-blue-700 bg-blue-50/50 dark:bg-blue-950/30 px-3 py-2 cursor-pointer hover:border-blue-500 hover:bg-blue-100/50 dark:hover:bg-blue-900/40 transition-all group ring-1 ring-blue-500/20 shadow-2xs"
                title={`Click to view all ${activeScan.cvesFound} findings in Vulnerability Management for ${activeScan.targetProject}`}
              >
                <p className="text-blue-600 dark:text-blue-400 font-bold flex items-center justify-between">
                  <span>Findings</span>
                  <ExternalLink className="w-3 h-3 opacity-0 group-hover:opacity-100 transition-opacity" />
                </p>
                <p className="text-lg font-bold text-blue-700 dark:text-blue-300">{activeScan.cvesFound}</p>
              </div>
              <div
                onClick={() => {
                  const params = new URLSearchParams({ project: activeScan.targetProject, severity: 'Critical' });
                  if (activeScan.id) params.set('scan', activeScan.id);
                  if (activeScan.appService) params.set('app', activeScan.appService);
                  navigate(`/vulnerabilities?${params.toString()}`);
                }}
                className="rounded-lg border border-gray-200 dark:border-gray-800 px-3 py-2 cursor-pointer hover:border-red-400 hover:bg-red-50/30 dark:hover:bg-red-950/20 transition-all group"
                title={`Click to view critical findings in Vulnerability Management`}
              >
                <p className="text-gray-500 flex items-center justify-between">
                  <span>Critical</span>
                  <ExternalLink className="w-3 h-3 text-red-400 opacity-0 group-hover:opacity-100 transition-opacity" />
                </p>
                <p className="text-lg font-bold text-red-600">{activeScan.criticals || 0}</p>
              </div>
              <div
                onClick={() => {
                  const params = new URLSearchParams({ project: activeScan.targetProject, severity: 'High' });
                  if (activeScan.id) params.set('scan', activeScan.id);
                  if (activeScan.appService) params.set('app', activeScan.appService);
                  navigate(`/vulnerabilities?${params.toString()}`);
                }}
                className="rounded-lg border border-gray-200 dark:border-gray-800 px-3 py-2 cursor-pointer hover:border-orange-400 hover:bg-orange-50/30 dark:hover:bg-orange-950/20 transition-all group"
                title={`Click to view high findings in Vulnerability Management`}
              >
                <p className="text-gray-500 flex items-center justify-between">
                  <span>High</span>
                  <ExternalLink className="w-3 h-3 text-orange-400 opacity-0 group-hover:opacity-100 transition-opacity" />
                </p>
                <p className="text-lg font-bold text-orange-500">{activeScan.highs || 0}</p>
              </div>
              <div
                onClick={() => {
                  const params = new URLSearchParams({ project: activeScan.targetProject, severity: 'Medium' });
                  if (activeScan.id) params.set('scan', activeScan.id);
                  if (activeScan.appService) params.set('app', activeScan.appService);
                  navigate(`/vulnerabilities?${params.toString()}`);
                }}
                className="rounded-lg border border-gray-200 dark:border-gray-800 px-3 py-2 cursor-pointer hover:border-amber-400 hover:bg-amber-50/30 dark:hover:bg-amber-950/20 transition-all group"
                title={`Click to view medium findings in Vulnerability Management`}
              >
                <p className="text-gray-500 flex items-center justify-between">
                  <span>Medium</span>
                  <ExternalLink className="w-3 h-3 text-amber-400 opacity-0 group-hover:opacity-100 transition-opacity" />
                </p>
                <p className="text-lg font-bold text-amber-500">{activeScan.mediums || 0}</p>
              </div>
              <div
                onClick={() => {
                  const params = new URLSearchParams({ project: activeScan.targetProject, severity: 'Low' });
                  if (activeScan.id) params.set('scan', activeScan.id);
                  if (activeScan.appService) params.set('app', activeScan.appService);
                  navigate(`/vulnerabilities?${params.toString()}`);
                }}
                className="rounded-lg border border-gray-200 dark:border-gray-800 px-3 py-2 cursor-pointer hover:border-sky-400 hover:bg-sky-50/30 dark:hover:bg-sky-950/20 transition-all group"
                title={`Click to view low findings in Vulnerability Management`}
              >
                <p className="text-gray-500 flex items-center justify-between">
                  <span>Low</span>
                  <ExternalLink className="w-3 h-3 text-sky-400 opacity-0 group-hover:opacity-100 transition-opacity" />
                </p>
                <p className="text-lg font-bold text-sky-500">{activeScan.lows || 0}</p>
              </div>
            </div>
          )}

          <div className="bg-gray-950 rounded-xl p-4 text-xs font-mono text-gray-300 space-y-1.5 shadow-inner max-h-52 overflow-y-auto">
            <div className="flex items-center justify-between text-gray-500 text-[11px] pb-2 border-b border-gray-800">
              <span className="flex items-center gap-1.5">
                <Terminal className="w-3.5 h-3.5 text-gray-400" />
                Scan stage log
              </span>
              <span>{pipelineScan?.events?.length ? `${pipelineScan.events.length} events` : 'Waiting for events'}</span>
            </div>
            {(pipelineScan?.events?.length ? pipelineScan.events : []).map((event) => (
              <p key={event.id} className="leading-relaxed">
                <span className="text-gray-600">[{formatEventTime(event.createdAt)}]</span> {event.stage}: {event.message}
              </p>
            ))}
            {!pipelineScan?.events?.length && (activeScan.logMessages || []).map((log, i) => (
              <p key={i} className="leading-relaxed">{log}</p>
            ))}
          </div>
        </div>
      ) : waitingScans.length > 0 ? null : (
        <div className="bg-white dark:bg-[#111827] border border-gray-200 dark:border-gray-800 rounded-xl p-12 text-center space-y-3 shadow-2xs">
          <div className="w-12 h-12 rounded-full bg-gray-100 dark:bg-gray-800 text-gray-400 flex items-center justify-center mx-auto">
            <Radio className="w-6 h-6" />
          </div>
          <h3 className="text-base font-bold text-gray-900 dark:text-white">
            No scans currently executing
          </h3>
          <p className="text-xs text-gray-500 max-w-sm mx-auto">
            All scheduled and manual jobs have completed. Launch a new scan from the New Scan tab.
          </p>
          <div className="flex items-center justify-center gap-3">
            <button
              type="button"
              onClick={onGoToLaunchScan}
              className="px-4 py-2 border border-gray-200 dark:border-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-800 text-xs font-semibold rounded-lg cursor-pointer transition-colors inline-flex items-center gap-1.5"
              title="Back to Launch Scan"
            >
              <ArrowLeft className="w-3.5 h-3.5" />
              Back
            </button>
            <button
              onClick={onGoToLaunchScan}
              className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-xs font-bold rounded-lg shadow-sm cursor-pointer"
            >
              + Launch New Scan
            </button>
          </div>
        </div>
      )}
    </div>
  );
};
