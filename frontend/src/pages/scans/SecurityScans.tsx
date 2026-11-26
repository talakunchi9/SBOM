import React, { useState, useEffect, useRef, useMemo } from 'react';
import { useParams, useNavigate, NavLink } from 'react-router-dom';
import {
  Folder,
  Layers,
  Upload,
  CheckCircle2,
  Info,
  ArrowRight,
  Shield,
  FileCode,
  Check,
  AlertTriangle,
  Github,
  Play,
  Ban,
  RotateCcw,
  RefreshCw,
  Clock,
  Calendar,
  History,
  Radio,
  PlusCircle,
  Terminal,
  Trash2,
  ExternalLink,
  Download,
  Filter,
  Search,
  X,
  FileSpreadsheet,
  Package,
  FolderGit2,
  Copy,
  MoreVertical,
  Plus,
  ArrowLeft,
  User,
  ChevronDown,
  FileText,
  FolderOpen,
} from 'lucide-react';
import { useAppState } from '../../context/AppStateContext';
import type { ScanJob } from '../../types';
import { ProjectApplicationSelect } from '../../components/common/ProjectApplicationSelect';
import { checkScanDuplicate, type CatalogRecord } from '../../api/client';
import {
  filesFromDataTransfer,
  fileTypesIn,
  folderLabel,
  folderStatsIn,
  folderTypeLabel,
  formatBytes,
  isArchiveName,
  isInsideSkippedDir,
  isManifestRelativePath,
  selectFolderManifests,
  SUPPORTED_MANIFEST_HINT,
  type FolderFile,
} from './localFolder';
import { classifyBulkCsv } from './bulkRows';
import * as XLSX from 'xlsx';
import { PipelineGrid, ScanResultDetails } from './ScanResultDetails';
import { displayStatus, formatDuration, formatEventTime, formatScanTimestamp12h, isOpenStatus, stageLabel } from './scanProgress';
import { ScanActionMenu } from './ScanActionMenu';
import { TablePagination } from '../../components/common/TablePagination';
import { ScansTableTab } from './components/ScansTableTab';
import { LiveScanMonitorTab } from './components/LiveScanMonitorTab';
import { ScanHistoryTab } from './components/ScanHistoryTab';
import { ScanSchedulesTab, CreateScheduleModal, type ScanScheduleItem } from './components/ScanSchedulesTab';

export const SecurityScans: React.FC = () => {
  const { tab } = useParams<{ tab?: string }>();
  const navigate = useNavigate();
  const { startScan, rescanScan, cancelScan, activeScan, scansHistory, exportSBOM, updateApplicationLifecycle, addToast } = useAppState();

  // Active sub-page tab: 'table' | 'new' | 'live' | 'history' | 'schedules'
  const validTabs = ['table', 'new', 'live', 'history', 'schedules'] as const;
  type TabType = (typeof validTabs)[number];
  const activeTab: TabType = validTabs.includes(tab as TabType) ? (tab as TabType) : 'table';

  const setTab = (newTab: TabType) => {
    if (newTab === 'table') {
      navigate('/security-scans');
    } else {
      navigate(`/security-scans/${newTab}`);
    }
  };

  // =========================================================================
  // SUB-PAGE 0: SECURITY SCANS TABLE (Landing view for Security Scans)
  // =========================================================================
  const [scanSearch, setScanSearch] = useState('');
  const [scanStatusFilter, setScanStatusFilter] = useState('All');
  const [scanTypeFilter, setScanTypeFilter] = useState('All');
  const [showScanFilters, setShowScanFilters] = useState(false);

  const filteredScans = scansHistory.filter((s) => {
    const q = scanSearch.toLowerCase();
    const matchSearch =
      !q ||
      s.targetProject.toLowerCase().includes(q) ||
      (s.appService && s.appService.toLowerCase().includes(q)) ||
      s.scanType.toLowerCase().includes(q) ||
      ((s as any).requestedBy && (s as any).requestedBy.toLowerCase().includes(q)) ||
      s.status.toLowerCase().includes(q);
    const matchStatus = scanStatusFilter === 'All'
      || s.status === scanStatusFilter
      || (scanStatusFilter === 'running' && s.status === 'analyzing');
    const matchType = scanTypeFilter === 'All' || s.scanType === scanTypeFilter;
    return matchSearch && matchStatus && matchType;
  });

  // Security Scans Table Pagination State
  const [scanPage, setScanPage] = useState<number>(1);
  const [scanPageSize, setScanPageSize] = useState<number>(15);

  useEffect(() => {
    setScanPage(1);
  }, [scanSearch, scanStatusFilter, scanTypeFilter]);

  const totalScans = filteredScans.length;
  const totalScanPages = Math.max(1, Math.ceil(totalScans / scanPageSize));
  const safeScanPage = Math.min(Math.max(1, scanPage), totalScanPages);
  const scanStartIndex = (safeScanPage - 1) * scanPageSize;
  const scanEndIndex = Math.min(scanStartIndex + scanPageSize, totalScans);
  const paginatedScans = filteredScans.slice(scanStartIndex, scanEndIndex);

  const handleResetScanFilters = () => {
    setScanSearch('');
    setScanStatusFilter('All');
    setScanTypeFilter('All');
    setScanPage(1);
  };

  // =========================================================================
  // SUB-PAGE 1: NEW SCAN (2-Stage Input & Review Flow as per Excel Sr 5)
  // =========================================================================
  const [newScanStep, setNewScanStep] = useState<'input' | 'review'>('input');
  const [launchFormKey, setLaunchFormKey] = useState(0);

  // Form State: Project Information
  const [selectedProject, setSelectedProject] = useState<CatalogRecord | null>(null);
  const [selectedApplication, setSelectedApplication] = useState<CatalogRecord | null>(null);
  const projectName = selectedProject?.name || '';
  const appService = selectedApplication?.name || '';
  const [releaseVersion, setReleaseVersion] = useState('v1.0.0');
  const [description, setDescription] = useState('');
  const [businessOwner, setBusinessOwner] = useState('');
  const [technicalOwner, setTechnicalOwner] = useState('');
  const [developmentType, setDevelopmentType] = useState<'In-house' | 'Outsourced' | 'Vendor'>('In-house');
  const [vendorName, setVendorName] = useState('');
  const [moduleType, setModuleType] = useState('Microservice');
  const [duplicateWarning, setDuplicateWarning] = useState<{
    isOpen: boolean;
    appName: string;
    moduleName: string;
    version: string;
    scannedAt: string;
    duplicateType?: string;
    fileName?: string;
  } | null>(null);

  // Source Type: 'local' | 'git' | 'bulk'
  const [sourceType, setSourceType] = useState<'local' | 'git' | 'bulk'>('local');

  // Local Source State
  const [selectedFolder, setSelectedFolder] = useState<string>('');
  const [localFile, setLocalFile] = useState<File | null>(null);
  const [localFolder, setLocalFolder] = useState<FolderFile[]>([]);
  const [showFileTree, setShowFileTree] = useState(false);
  const [fileFilter, setFileFilter] = useState('');
  const fileInputRef = useRef<HTMLInputElement>(null);
  const folderInputRef = useRef<HTMLInputElement>(null);

  const localFolderStats = useMemo(() => {
    return folderStatsIn(localFolder);
  }, [localFolder]);

  const filteredLocalFiles = useMemo(() => {
    if (!fileFilter.trim()) return localFolder;
    const q = fileFilter.toLowerCase();
    return localFolder.filter((item) => item.relativePath.toLowerCase().includes(q));
  }, [localFolder, fileFilter]);

  const [isDraggingOverCard, setIsDraggingOverCard] = useState(false);

  // Local Source Upload Tabbed Modal State (matches user reference design)
  const [localUploadModalOpen, setLocalUploadModalOpen] = useState(false);
  const [localModalTab, setLocalModalTab] = useState<'files' | 'folder'>('files');
  const [pendingLocalFile, setPendingLocalFile] = useState<File | null>(null);
  const [pendingLocalFolder, setPendingLocalFolder] = useState<FolderFile[]>([]);
  const modalFileInputRef = useRef<HTMLInputElement>(null);
  const modalFolderInputRef = useRef<HTMLInputElement>(null);

  const openLocalUploadModal = (initialTab: 'files' | 'folder' = 'files') => {
    setLocalModalTab(localFolder.length > 0 ? 'folder' : initialTab);
    setPendingLocalFile(localFile);
    setPendingLocalFolder(localFolder);
    setLocalUploadModalOpen(true);
  };

  const clearLocalSelection = () => {
    setSelectedFolder('');
    setLocalFile(null);
    setLocalFolder([]);
    setPendingLocalFile(null);
    setPendingLocalFolder([]);
    setShowFileTree(false);
    setFileFilter('');
    if (fileInputRef.current) fileInputRef.current.value = '';
    if (folderInputRef.current) folderInputRef.current.value = '';
    if (modalFileInputRef.current) modalFileInputRef.current.value = '';
    if (modalFolderInputRef.current) modalFolderInputRef.current.value = '';
  };

  const checkDuplicateForFile = async (fileToCheck: File) => {
    try {
      const dup = await checkScanDuplicate({
        applicationName: projectName.trim(),
        moduleName: appService.trim(),
        version: releaseVersion.trim(),
        file: fileToCheck,
      });
      if (dup?.is_duplicate) {
        setDuplicateWarning({
          isOpen: true,
          appName: dup.application_name || projectName.trim() || 'Existing Application',
          moduleName: dup.module_name || appService.trim() || 'Existing Module',
          version: dup.version || releaseVersion.trim() || 'v1.0.0',
          scannedAt: dup.completed_at ? formatScanTimestamp12h(dup.completed_at) : 'Previously',
          duplicateType: dup.duplicate_type,
          fileName: fileToCheck.name,
        });
        return true;
      }
    } catch {
      // ignore
    }
    return false;
  };

  const openFolderPicker = () => {
    const input = folderInputRef.current;
    if (!input) return;
    input.value = '';
    input.multiple = true;
    input.accept = '';
    input.removeAttribute('accept');
    // Whole project / mixed-manifest folder upload.
    input.setAttribute('webkitdirectory', '');
    input.setAttribute('directory', '');
    input.click();
  };

  const openFilePicker = () => {
    const input = fileInputRef.current;
    if (!input) return;
    input.value = '';
    input.multiple = true;
    input.removeAttribute('webkitdirectory');
    input.removeAttribute('directory');
    input.click();
  };

  const useFolderManifests = (items: FolderFile[]) => {
    const nonSkipped = items.filter((item) => {
      const rel = item.relativePath.replace(/\\/g, '/');
      return rel !== '' && !isInsideSkippedDir(rel);
    });
    const finalItems = nonSkipped.length > 0 ? nonSkipped : items;
    const manifests = selectFolderManifests(finalItems);
    setSelectedFolder(folderTypeLabel(finalItems, manifests));
    if (finalItems.length === 0 || finalItems.every((item) => item.file.size === 0)) {
      setLocalFile(null);
      setLocalFolder([]);
      setSelectedFolder('');
      addToast({
        type: 'error',
        title: 'Empty Folder',
        message: 'The selected folder contains no files or only empty files (0 bytes). Empty folders cannot be scanned.',
      });
      return;
    }
    setLocalFile(null);
    // Allow importing all files and folders within the selected folder
    setLocalFolder(finalItems);

    if (manifests.length > 0) {
      const firstLower = manifests[0].file.name.toLowerCase();
      if (firstLower.includes('cyclonedx') || firstLower === 'bom.json' || firstLower === 'bom.xml') {
        setSbomFormat('CYCLONE DX');
      } else if (firstLower.includes('spdx')) {
        setSbomFormat('SPDX');
      }
    }
  };

  const acceptLocalDrop = async (dt: DataTransfer) => {
    const items = await filesFromDataTransfer(dt);
    if (!items || items.length === 0) {
      addToast({
        type: 'error',
        title: 'Empty Drop',
        message: 'No files were dropped or the dropped item was empty. Empty items cannot be scanned.',
      });
      return;
    }
    const nested = items.some((item) => item.relativePath.includes('/'));
    if (!nested && items.length === 1) {
      const droppedFile = items[0].file;
      if (droppedFile.size === 0) {
        setLocalFile(null);
        setLocalFolder([]);
        setSelectedFolder('');
        addToast({
          type: 'error',
          title: 'Empty File',
          message: `The file "${droppedFile.name}" is empty (0 bytes). Empty files cannot be scanned.`,
        });
        return;
      }
      setLocalFolder([]);
      setLocalFile(droppedFile);
      setSelectedFolder(droppedFile.name);
      const name = droppedFile.name.toLowerCase();
      if (name.includes('cyclonedx') || name === 'bom.json' || name === 'bom.xml') {
        setSbomFormat('CYCLONE DX');
      } else if (name.includes('spdx')) {
        setSbomFormat('SPDX');
      }
      checkDuplicateForFile(droppedFile);
      return;
    }
    useFolderManifests(items);
  };

  // Remote Git State (GitHub only)
  const [gitUrl, setGitUrl] = useState('');
  const [gitBranch, setGitBranch] = useState('main');
  const [gitToken, setGitToken] = useState('');

  // Bulk Scan State & Spreadsheet Matrix Support
  const bulkFileInputRef = useRef<HTMLInputElement>(null);
  const [uploadedBulk, setUploadedBulk] = useState<File | null>(null);
  const [bulkMode, setBulkMode] = useState<'file' | 'manual'>('file');
  const [bulkScanList, setBulkScanList] = useState(
    'https://github.com/expressjs/express\nhttps://github.com/pallets/flask\nhttps://github.com/fastapi/fastapi\nhttps://github.com/gin-gonic/gin'
  );

  interface BulkProjectRow {
    id: string;
    rowNumber?: number;
    project: string;
    name: string;
    version: string;
    source: string;
    branch: string;
    ecosystem: string;
    rowStatus?: 'ready' | 'duplicate' | 'invalid';
    rowMessage?: string;
  }

  const [bulkFile, setBulkFile] = useState<{
    name: string;
    size: string;
    rowCount: number;
    uploadedAt: string;
  }>({
    name: 'squad1_bulk_scan_template.csv',
    size: '0.8 KB',
    rowCount: 0,
    uploadedAt: 'Sample Template',
  });

  const [bulkFileError, setBulkFileError] = useState('');
  const [bulkProjects, setBulkProjects] = useState<BulkProjectRow[]>([]);

  const handleDownloadSampleCsv = () => {
    const link = document.createElement('a');
    link.href = '/squad1_bulk_scan_template.csv';
    link.download = 'squad1_bulk_scan_template.csv';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);

    addToast({
      type: 'success',
      title: 'Template Downloaded',
      message: 'Downloaded squad1_bulk_scan_template.csv for batch inventory scanning.',
    });
  };

  const handleBulkFile = async (file: File) => {
    if (!file) return;

    if (file.size === 0) {
      setUploadedBulk(null);
      setBulkFileError(`The file "${file.name}" is empty (0 bytes).`);
      setBulkProjects([]);
      setBulkFile({
        name: file.name,
        size: '0.0 KB',
        rowCount: 0,
        uploadedAt: 'Empty file',
      });
      addToast({
        type: 'error',
        title: 'Empty File',
        message: `The spreadsheet file "${file.name}" is empty (0 bytes). Empty files cannot be scanned.`,
      });
      if (bulkFileInputRef.current) bulkFileInputRef.current.value = '';
      return;
    }

    setUploadedBulk(file);
    const fileSizeKB = (file.size / 1024).toFixed(1) + ' KB';
    const fileName = file.name;
    const isCsv = fileName.toLowerCase().endsWith('.csv');

    const processClassifiedText = (csvText: string, isExcel = false) => {
      if (!csvText.trim()) {
        setUploadedBulk(null);
        setBulkFileError('The spreadsheet file contains no data.');
        setBulkProjects([]);
        setBulkFile({
          name: fileName,
          size: fileSizeKB,
          rowCount: 0,
          uploadedAt: 'Empty file',
        });
        addToast({
          type: 'error',
          title: 'Empty File',
          message: `The file "${fileName}" contains no data rows. Empty spreadsheets cannot be scanned.`,
        });
        if (bulkFileInputRef.current) bulkFileInputRef.current.value = '';
        return;
      }
      const classified = classifyBulkCsv(csvText);
      if (classified.fileError) {
        setUploadedBulk(null);
        setBulkFileError(classified.fileError);
        setBulkProjects([]);
        setBulkFile({
          name: fileName,
          size: fileSizeKB,
          rowCount: 0,
          uploadedAt: 'Cannot scan',
        });
        addToast({ type: 'error', title: 'Spreadsheet cannot be scanned', message: classified.fileError });
        if (bulkFileInputRef.current) bulkFileInputRef.current.value = '';
        return;
      }
      if (classified.rows.length === 0) {
        setUploadedBulk(null);
        setBulkFileError('The spreadsheet contains no project rows to scan.');
        setBulkProjects([]);
        setBulkFile({
          name: fileName,
          size: fileSizeKB,
          rowCount: 0,
          uploadedAt: 'Empty spreadsheet',
        });
        addToast({
          type: 'error',
          title: 'Empty Spreadsheet',
          message: `The file "${fileName}" contains no data rows. Empty spreadsheets cannot be scanned.`,
        });
        if (bulkFileInputRef.current) bulkFileInputRef.current.value = '';
        return;
      }
      const skipped = classified.rows.filter((row) => row.rowStatus !== 'ready').length;
      setBulkFileError('');
      setBulkProjects(classified.rows);
      setBulkFile({
        name: fileName,
        size: fileSizeKB,
        rowCount: classified.rows.length,
        uploadedAt: 'Just now',
      });
      setBulkScanList(classified.rows.map((row) => row.source).join('\n'));
      addToast({
        type: skipped ? 'warning' : 'success',
        title: skipped
          ? 'Spreadsheet needs review'
          : isExcel
            ? 'Excel Matrix Imported'
            : 'CSV Matrix Imported',
        message: skipped
          ? `${classified.rows.length - skipped} rows will be scanned. ${skipped} duplicate or invalid ${skipped === 1 ? 'row is' : 'rows are'} skipped.`
          : `Successfully loaded ${classified.rows.length} projects from ${fileName}.`,
      });
    };

    if (isCsv) {
      const reader = new FileReader();
      reader.onload = (event) => {
        const text = (event.target?.result as string) || '';
        processClassifiedText(text, false);
      };
      reader.readAsText(file);
    } else {
      try {
        const buffer = await file.arrayBuffer();
        const workbook = XLSX.read(buffer, { type: 'array' });
        const sheetName = workbook.SheetNames[0];
        const sheet = sheetName ? workbook.Sheets[sheetName] : null;
        if (!sheet) {
          throw new Error('Workbook contains no sheets.');
        }
        const csvText = XLSX.utils.sheet_to_csv(sheet);
        processClassifiedText(csvText, true);
      } catch (err: any) {
        setUploadedBulk(null);
        setBulkFileError('Could not read Excel file.');
        setBulkProjects([]);
        addToast({
          type: 'error',
          title: 'Invalid File',
          message: `Failed to parse Excel file "${fileName}". Please check the file.`,
        });
        if (bulkFileInputRef.current) bulkFileInputRef.current.value = '';
      }
    }
  };

  const handleBulkFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) void handleBulkFile(file);
  };

  // Scan Configuration State
  const [sbomFormat, setSbomFormat] = useState<'SPDX' | 'CYCLONE DX'>('SPDX');

  const resetLaunchForm = () => {
    setNewScanStep('input');
    setSelectedProject(null);
    setSelectedApplication(null);
    setReleaseVersion('v1.0.0');
    setDescription('');
    setBusinessOwner('');
    setTechnicalOwner('');
    setDevelopmentType('In-house');
    setVendorName('');
    setModuleType('Microservice');
    setDuplicateWarning(null);
    setSourceType('local');
    setSelectedFolder('');
    setLocalFile(null);
    setLocalFolder([]);
    setShowFileTree(false);
    setFileFilter('');
    setGitUrl('');
    setGitBranch('main');
    setGitToken('');
    setUploadedBulk(null);
    setBulkMode('file');
    setBulkFileError('');
    setBulkProjects([]);
    setBulkFile({
      name: 'squad1_bulk_scan_template.csv',
      size: '0.8 KB',
      rowCount: 0,
      uploadedAt: 'Sample Template',
    });
    if (fileInputRef.current) fileInputRef.current.value = '';
    if (folderInputRef.current) folderInputRef.current.value = '';
    if (bulkFileInputRef.current) bulkFileInputRef.current.value = '';
  };

  const goToLaunchScan = () => {
    resetLaunchForm();
    setLaunchFormKey((key) => key + 1);
    setTab('new');
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  // Computes the correct file format for the selected scan source
  const getPrimaryFormatLabel = (): string => {
    if (sourceType === 'bulk') {
      if (bulkMode === 'file') {
        const name = (uploadedBulk?.name || bulkFile?.name || '').toLowerCase();
        if (name.endsWith('.xlsx')) return 'Excel (.xlsx)';
        if (name.endsWith('.xls')) return 'Excel (.xls)';
        if (name.endsWith('.csv')) return 'CSV (.csv)';
        return 'Spreadsheet (.csv, .xlsx, .xls)';
      }
      return 'Plain Text (Git URLs)';
    }

    if (sourceType === 'git') {
      return 'Remote Git Repository';
    }

    if (localFile) {
      const name = localFile.name.toLowerCase();
      if (name.endsWith('.json')) {
        if (name.includes('cyclonedx') || name === 'bom.json') return 'CycloneDX JSON (.json)';
        if (name.includes('spdx')) return 'SPDX JSON (.json)';
        return 'JSON (.json)';
      }
      if (name.endsWith('.xml')) {
        if (name.includes('cyclonedx') || name === 'bom.xml') return 'CycloneDX XML (.xml)';
        if (name.includes('spdx')) return 'SPDX XML (.xml)';
        return 'XML (.xml)';
      }
      if (name.endsWith('.zip')) return 'ZIP Archive (.zip)';
      if (name.endsWith('.tar.gz') || name.endsWith('.tgz')) return 'Tar Archive (.tgz)';
      if (name.endsWith('.txt')) return 'Text Manifest (.txt)';
      if (name.endsWith('.lock')) return 'Lockfile (.lock)';
      if (name.endsWith('.yaml') || name.endsWith('.yml')) return 'YAML (.yaml)';
      if (name.endsWith('.toml')) return 'TOML (.toml)';
      if (name.endsWith('.gradle') || name.endsWith('.kts')) return 'Gradle Script (.gradle)';
      if (name.endsWith('.mod') || name.endsWith('.sum')) return 'Go Module (.mod)';
      if (name.endsWith('.csproj') || name.endsWith('.vbproj') || name.endsWith('.fsproj')) return '.NET Project';

      const parts = name.split('.');
      if (parts.length > 1) {
        const ext = parts.pop();
        return `${ext?.toUpperCase()} (.${ext})`;
      }
      return 'Source File';
    }

    if (localFolder && localFolder.length > 0) {
      const types = fileTypesIn(localFolder);
      if (types.length > 0) {
        return `Project Directory (${types.map((t: string) => t.toUpperCase()).slice(0, 3).join(', ')})`;
      }
      return 'Project Directory (Multi-Manifest)';
    }

    if (selectedFolder) {
      const lower = selectedFolder.toLowerCase();
      if (lower.endsWith('.zip')) return 'ZIP Archive (.zip)';
      if (lower.endsWith('.json')) return 'JSON (.json)';
      if (lower.endsWith('.xml')) return 'XML (.xml)';
      if (lower.endsWith('.csv')) return 'CSV (.csv)';
      if (lower.endsWith('.txt')) return 'Text Manifest (.txt)';
      return 'Local Source Directory';
    }

    return 'CycloneDX (JSON)';
  };

  // Tooltip State (Excel Sr 9: hover info icons)
  const [activeTooltip, setActiveTooltip] = useState<string | null>(null);

  // Submission State
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Advance to Review with Duplicate Preflight Check
  const handleProceedToReview = async (e: React.FormEvent) => {
    e.preventDefault();
    if (sourceType !== 'bulk') {
      if (!projectName.trim() && !selectedProject?.id) {
        addToast({ type: 'warning', title: 'Validation Error', message: 'Application Name is required.' });
        return;
      }
      if (!appService.trim() && !selectedApplication?.id) {
        addToast({ type: 'warning', title: 'Validation Error', message: 'Module / Service is required.' });
        return;
      }
      if (!releaseVersion || !releaseVersion.trim()) {
        addToast({ type: 'warning', title: 'Validation Error', message: 'Release / Version is required (e.g. v1.0.0).' });
        return;
      }
      if (!businessOwner || !businessOwner.trim()) {
        addToast({ type: 'warning', title: 'Validation Error', message: 'Business Owner is required (e.g. Finance Team).' });
        return;
      }
      if (!technicalOwner || !technicalOwner.trim()) {
        addToast({ type: 'warning', title: 'Validation Error', message: 'Technical Owner is required (e.g. @core-devs / Alice).' });
        return;
      }
      // Preflight duplicate check before proceeding
      try {
        const dup = await checkScanDuplicate({
          applicationName: projectName.trim(),
          moduleName: appService.trim(),
          version: releaseVersion.trim(),
          file: localFile,
          folderFiles: localFolder,
          repositoryUrl: sourceType === 'git' ? gitUrl.trim() : undefined,
          branch: sourceType === 'git' ? gitBranch.trim() : undefined,
        });
        if (dup?.is_duplicate) {
          setDuplicateWarning({
            isOpen: true,
            appName: dup.application_name || projectName.trim(),
            moduleName: dup.module_name || appService.trim(),
            version: dup.version || releaseVersion.trim(),
            scannedAt: dup.completed_at ? formatScanTimestamp12h(dup.completed_at) : 'Previously',
            duplicateType: dup.duplicate_type,
            fileName: localFile?.name || (localFolder.length > 0 ? `${localFolder.length} files` : undefined),
          });
          return;
        }
      } catch (err) {
        // Continue if preflight check is unavailable
      }
    }
    if (sourceType === 'local') {
      if (!localFile && localFolder.length === 0) {
        addToast({ type: 'warning', title: 'Source Required', message: 'Choose a project folder, a single manifest file, or a .zip archive.' });
        return;
      }
      if (localFile && localFile.size === 0) {
        addToast({ type: 'error', title: 'Empty File', message: `The file "${localFile.name}" is empty (0 bytes). Empty files cannot be scanned.` });
        return;
      }
      if (localFolder.length > 0 && localFolder.every((f) => f.file.size === 0)) {
        addToast({ type: 'error', title: 'Empty Folder', message: 'The selected folder contains only empty files (0 bytes). Empty folders cannot be scanned.' });
        return;
      }
    }
    if (sourceType === 'bulk' && bulkMode === 'file') {
      if (!uploadedBulk) {
        addToast({ type: 'warning', title: 'Spreadsheet Required', message: 'Upload a CSV, XLSX, or XLS spreadsheet before proceeding.' });
        return;
      }
      if (uploadedBulk.size === 0) {
        addToast({ type: 'error', title: 'Empty File', message: `The spreadsheet file "${uploadedBulk.name}" is empty (0 bytes). Empty files cannot be scanned.` });
        return;
      }
      if (bulkFileError) {
        addToast({ type: 'error', title: 'Spreadsheet cannot be scanned', message: bulkFileError });
        return;
      }
      if (bulkProjects.length === 0) {
        addToast({ type: 'error', title: 'Empty Spreadsheet', message: 'The spreadsheet contains no project rows to scan.' });
        return;
      }
      if (bulkProjects.length > 0 && bulkProjects.every((row) => row.rowStatus && row.rowStatus !== 'ready')) {
        addToast({
          type: 'warning',
          title: 'Nothing to scan',
          message: 'Every row is a duplicate project or invalid. Fix the spreadsheet and upload it again. Valid rows in a mixed file are still scanned.',
        });
        return;
      }
    }
    setNewScanStep('review');
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  // Final Launch Scan (Excel Sr 8) -> Transitions to Live Jobs
  const handleFinalLaunchScan = async () => {
    const manualUrls = bulkScanList.split(/\r?\n/).map((line) => line.trim()).filter((line) => line.startsWith('https://github.com/'));
    if (sourceType === 'local') {
      if (!localFile && localFolder.length === 0) {
        addToast({ type: 'warning', title: 'Source Required', message: 'Choose a project folder, a single manifest file, or a .zip archive.' });
        return;
      }
      if (localFile && localFile.size === 0) {
        addToast({ type: 'error', title: 'Empty File', message: `The file "${localFile.name}" is empty (0 bytes). Empty files cannot be scanned.` });
        return;
      }
      if (localFolder.length > 0 && localFolder.every((f) => f.file.size === 0)) {
        addToast({ type: 'error', title: 'Empty Folder', message: 'The selected folder contains only empty files (0 bytes). Empty folders cannot be scanned.' });
        return;
      }
    }
    if (sourceType === 'git' && !gitUrl.trim().startsWith('https://github.com/')) {
      addToast({ type: 'warning', title: 'GitHub URL required', message: 'Use a URL that starts with https://github.com/.' });
      return;
    }
    if (sourceType === 'bulk' && bulkMode === 'file') {
      if (!uploadedBulk) {
        addToast({ type: 'warning', title: 'Spreadsheet required', message: 'Upload a CSV, XLSX, or XLS that uses the template columns.' });
        return;
      }
      if (uploadedBulk.size === 0) {
        addToast({ type: 'error', title: 'Empty File', message: `The spreadsheet file "${uploadedBulk.name}" is empty (0 bytes). Empty files cannot be scanned.` });
        return;
      }
      if (bulkFileError) {
        addToast({ type: 'error', title: 'Spreadsheet cannot be scanned', message: bulkFileError });
        return;
      }
      if (bulkProjects.length === 0) {
        addToast({ type: 'error', title: 'Empty Spreadsheet', message: 'The spreadsheet contains no project rows to scan.' });
        return;
      }
    }
    if (sourceType === 'bulk' && bulkMode === 'manual' && manualUrls.length === 0) {
      addToast({ type: 'warning', title: 'Repositories required', message: 'Enter one https://github.com/owner/repo URL per line.' });
      return;
    }
    if (sourceType !== 'bulk' && (!businessOwner || !businessOwner.trim())) {
      addToast({ type: 'warning', title: 'Validation Error', message: 'Business Owner is required (e.g. Finance Team).' });
      return;
    }
    if (sourceType !== 'bulk' && (!technicalOwner || !technicalOwner.trim())) {
      addToast({ type: 'warning', title: 'Validation Error', message: 'Technical Owner is required (e.g. @core-devs / Alice).' });
      return;
    }

    setIsSubmitting(true);
    const sourceDesc =
      sourceType === 'local'
        ? localFile?.name || selectedFolder
        : sourceType === 'git'
          ? `${gitUrl} (${gitBranch})`
          : bulkMode === 'file'
            ? uploadedBulk?.name || bulkFile.name
            : `${manualUrls.length} GitHub repositories`;

    const bulkFileToSend = sourceType !== 'bulk'
      ? null
      : bulkMode === 'file'
        ? uploadedBulk
        : new File(
          [
            'project_name,application_name,version,repository_url,branch,authentication_reference,scan_type\n' +
            manualUrls.map((url) => {
              const parts = url.split('/').filter(Boolean);
              const name = parts.pop() || 'app';
              const owner = parts.pop() || name;
              return [owner, name, 'UNKNOWN', url, 'main', '', 'GITHUB']
                .map((cell) => `"${String(cell).replace(/"/g, '""')}"`)
                .join(',');
            }).join('\n') + '\n',
          ],
          'bulk.csv',
          { type: 'text/csv' },
        );

    try {
      const firstBulk = bulkProjects.find((row) => !row.rowStatus || row.rowStatus === 'ready') || bulkProjects[0];
      const scanId = await startScan({
        projectName: sourceType === 'bulk' ? (projectName.trim() || firstBulk?.project || 'Bulk scan') : projectName,
        appService: sourceType === 'bulk' ? (appService.trim() || firstBulk?.name || '') : appService,
        projectId: sourceType === 'bulk' ? undefined : selectedProject?.id,
        applicationId: sourceType === 'bulk' ? undefined : selectedApplication?.id,
        releaseTag: sourceType === 'bulk' ? (releaseVersion.trim() || firstBulk?.version || '') : releaseVersion,
        scanType: sourceType === 'local' ? 'Local Source' : sourceType === 'git' ? 'Remote Git' : 'Bulk Scan',
        source: sourceDesc,
        description: description.trim(),
        localFile,
        localFolder,
        bulkFile: bulkFileToSend,
        gitUrl,
        gitBranch,
        gitToken,
        businessOwner,
        technicalOwner,
        developmentType,
        vendorName,
        moduleType,
      });

      setIsSubmitting(false);
      if (scanId) {
        resetLaunchForm();
        setTab('live');
      }
    } catch (err) {
      setIsSubmitting(false);
      addToast({
        type: 'error',
        title: 'Scan was not queued',
        message: err instanceof Error ? err.message : 'The scan API rejected the request.',
      });
    }
  };

  // =========================================================================
  // SUB-PAGE 2: LIVE JOBS STATE & LOGIC
  // =========================================================================
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!activeScan || !isOpenStatus(activeScan.status)) return;
    const interval = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(interval);
  }, [activeScan?.id, activeScan?.status]);

  const scanFailed = activeScan?.status === 'failed';
  const bulkChildren = activeScan?.isBulkAggregate
    ? scansHistory.filter((scan) => scan.bulkId === activeScan.bulkId && !scan.isBulkAggregate)
    : [];
  const pipelineScan = activeScan?.isBulkAggregate
    ? bulkChildren.find((scan) => scan.status === 'running' || scan.status === 'analyzing') || null
    : activeScan;

  // =========================================================================
  // SUB-PAGE 3: SCAN HISTORY STATE & DETAIL MODAL
  // =========================================================================
  const [historySearch, setHistorySearch] = useState('');
  const [historyStatusFilter, setHistoryStatusFilter] = useState('All');
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null);
  const selectedHistoryScan = scansHistory.find((scan) => scan.id === selectedScanId) || null;
  const [rescanningId, setRescanningId] = useState<string | null>(null);
  const [cancellingId, setCancellingId] = useState<string | null>(null);
  const [rescanTargetJob, setRescanTargetJob] = useState<ScanJob | null>(null);
  const [rescanSourceChoice, setRescanSourceChoice] = useState<'previous' | 'new_file'>('previous');
  const [rescanNewFile, setRescanNewFile] = useState<File | null>(null);
  const rescanFileInputRef = useRef<HTMLInputElement>(null);

  const canRescan = (status: string) => status === 'completed' || status === 'failed' || status === 'cancelled';
  const canCancel = (status: string) => {
    const normalized = status.toLowerCase();
    return normalized === 'queued' || normalized === 'pending' || normalized === 'running' || normalized === 'analyzing';
  };
  const waitingScans = scansHistory.filter((scan) => scan.status === 'queued' && scan.id !== activeScan?.id);

  const handleCancel = async (job: ScanJob) => {
    if (cancellingId) return;
    setCancellingId(job.id);
    try {
      if (job.isBulkAggregate) {
        const children = scansHistory.filter((scan) => scan.bulkId === job.bulkId && !scan.isBulkAggregate && canCancel(scan.status));
        if (children.length === 0) {
          addToast({ type: 'info', title: 'Nothing to cancel', message: 'Every row in this batch has already finished.' });
          return;
        }
        for (const child of children) {
          await cancelScan(child);
        }
        return;
      }
      await cancelScan(job);
    } catch (err) {
      addToast({
        type: 'error',
        title: 'Cancel failed',
        message: err instanceof Error ? err.message : 'The scan could not be cancelled.',
      });
    } finally {
      setCancellingId(null);
    }
  };

  const handleRescan = (job: ScanJob) => {
    setRescanTargetJob(job);
    setRescanSourceChoice('previous');
    setRescanNewFile(null);
  };

  const executeRescan = async () => {
    if (!rescanTargetJob || rescanningId) return;

    if (rescanSourceChoice === 'new_file') {
      if (!rescanNewFile) {
        addToast({
          type: 'warning',
          title: 'File Required',
          message: 'Please choose a new manifest or archive file to scan.',
        });
        return;
      }
      setRescanningId(rescanTargetJob.id);
      try {
        const scanId = await startScan({
          projectName: rescanTargetJob.targetProject,
          appService: rescanTargetJob.appService || '',
          releaseTag: rescanTargetJob.releaseTag || 'v1.0.0',
          scanType: 'Local Source',
          source: rescanNewFile.name,
          localFile: rescanNewFile,
        });
        setRescanTargetJob(null);
        setSelectedScanId(null);
        if (scanId) {
          setTab('live');
        }
        addToast({
          type: 'success',
          title: 'Rescan Started',
          message: `Rescanning ${rescanTargetJob.targetProject} with new file: ${rescanNewFile.name}.`,
        });
      } catch (err) {
        addToast({
          type: 'error',
          title: 'Rescan failed',
          message: err instanceof Error ? err.message : 'The scan could not be queued.',
        });
      } finally {
        setRescanningId(null);
      }
    } else {
      setRescanningId(rescanTargetJob.id);
      try {
        await rescanScan(rescanTargetJob);
        setRescanTargetJob(null);
        setSelectedScanId(null);
        setTab('live');
      } catch (err) {
        addToast({
          type: 'error',
          title: 'Rescan failed',
          message: err instanceof Error ? err.message : 'The scan could not be queued again.',
        });
      } finally {
        setRescanningId(null);
      }
    }
  };

  const filteredHistory = scansHistory.filter((s) => {
    const matchSearch =
      !historySearch ||
      s.targetProject.toLowerCase().includes(historySearch.toLowerCase()) ||
      s.id.toLowerCase().includes(historySearch.toLowerCase());
    const matchStatus = historyStatusFilter === 'All'
      || s.status === historyStatusFilter
      || (historyStatusFilter === 'running' && s.status === 'analyzing');
    return matchSearch && matchStatus;
  });

  const SCHEDULES_STORAGE_KEY = 'squad1_sbom_schedules';

  const [schedulesList, setSchedulesList] = useState<ScanScheduleItem[]>(() => {
    try {
      const saved = localStorage.getItem(SCHEDULES_STORAGE_KEY);
      if (saved) return JSON.parse(saved);
    } catch (e) {
      console.error('Failed to parse saved schedules', e);
    }
    return [];
  });

  useEffect(() => {
    try {
      localStorage.setItem(SCHEDULES_STORAGE_KEY, JSON.stringify(schedulesList));
    } catch (e) {
      console.error('Failed to persist schedules', e);
    }
  }, [schedulesList]);

  const [createScheduleModalOpen, setCreateScheduleModalOpen] = useState(false);
  const [newSchedName, setNewSchedName] = useState('');
  const [newSchedProject, setNewSchedProject] = useState('Payments API');
  const [newSchedFreq, setNewSchedFreq] = useState('Daily');
  const [newSchedDate, setNewSchedDate] = useState<string>(() => {
    const d = new Date();
    d.setDate(d.getDate() + 1);
    return d.toISOString().split('T')[0];
  });
  const [newSchedTime, setNewSchedTime] = useState<string>('02:00');
  const [newSchedTimezone, setNewSchedTimezone] = useState<string>('UTC');

  const handleCreateSchedule = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newSchedName.trim()) return;

    const formattedNextRun = `${newSchedDate}, ${newSchedTime} ${newSchedTimezone}`;
    const formattedFrequency = `${newSchedFreq} @ ${newSchedTime} ${newSchedTimezone}`;

    const newSched = {
      id: `sched-${Date.now()}`,
      name: newSchedName,
      project: newSchedProject,
      frequency: formattedFrequency,
      days: newSchedFreq === 'Daily' ? 'Daily' : newSchedFreq.startsWith('Weekly') ? 'Weekly' : newSchedFreq.startsWith('Monthly') ? 'Monthly' : 'One-time',
      nextRun: formattedNextRun,
      lastRun: 'Never',
      enabled: true,
    };

    setSchedulesList((prev) => [newSched, ...prev]);
    setCreateScheduleModalOpen(false);
    setNewSchedName('');
    addToast({
      type: 'success',
      title: 'Schedule Created',
      message: `Automated scan schedule configured for ${formattedNextRun}.`,
    });
  };

  const toggleSchedule = (id: string) => {
    setSchedulesList((prev) =>
      prev.map((s) => (s.id === id ? { ...s, enabled: !s.enabled } : s))
    );
  };

  return (
    <div className="space-y-6 w-full mx-auto pb-16 animate-fadeIn">
      {/* ========================================================================= */}
      {/* 0. COMPONENTS TABLE SUB-PAGE (DEFAULT VIEW FOR SECURITY SCANS)            */}
      {/* ========================================================================= */}
      {activeTab === 'table' && (
        <ScansTableTab
          scanSearch={scanSearch}
          onScanSearchChange={setScanSearch}
          showScanFilters={showScanFilters}
          onToggleScanFilters={() => setShowScanFilters((prev) => !prev)}
          scanStatusFilter={scanStatusFilter}
          onScanStatusFilterChange={setScanStatusFilter}
          scanTypeFilter={scanTypeFilter}
          onScanTypeFilterChange={setScanTypeFilter}
          onResetFilters={handleResetScanFilters}
          onLaunchScan={goToLaunchScan}
          filteredScans={filteredScans}
          paginatedScans={paginatedScans}
          safeScanPage={safeScanPage}
          totalScans={totalScans}
          scanPageSize={scanPageSize}
          onPageChange={setScanPage}
          onPageSizeChange={setScanPageSize}
          rescanningId={rescanningId}
          onSelectScan={setSelectedScanId}
          onExport={exportSBOM}
          onRescan={handleRescan}
          onToggleLifecycle={(scan, newStatus) => updateApplicationLifecycle(scan.targetProject, newStatus)}
        />
      )}

      {/* ========================================================================= */}
      {/* 1. NEW SCAN SUB-PAGE                                                      */}
      {/* ========================================================================= */}
      {activeTab === 'new' && (
        <div key={launchFormKey} className="space-y-6">
          <div className="flex items-center justify-between pb-1">
            <button
              type="button"
              onClick={() => setTab('table')}
              className="inline-flex items-center gap-1.5 text-xs font-semibold text-gray-600 dark:text-gray-400 hover:text-blue-600 dark:hover:text-blue-400 cursor-pointer transition-colors"
            >
              <ArrowLeft className="w-3.5 h-3.5" />
              <span>Back to Security Scans</span>
            </button>
          </div>
          {newScanStep === 'input' ? (
            <form onSubmit={handleProceedToReview} className="space-y-6">
              {/* SECTION 1: Project Information. Required for local and Git; optional for bulk, which reads these from the file. */}
              <div className="bg-white dark:bg-[#111827] border border-gray-200 dark:border-gray-800 rounded-xl p-5 shadow-2xs space-y-4">
                <div className="flex items-center justify-between pb-3 border-b border-gray-100 dark:border-gray-800">
                  <div className="flex items-center gap-2">
                    <h2 className="text-sm font-bold text-gray-900 dark:text-white">
                      1. Project Information
                    </h2>
                    {/* Hover Info Tooltip (Excel Sr 9) */}
                    <div className="relative">
                      <button
                        type="button"
                        onMouseEnter={() => setActiveTooltip('project-info')}
                        onMouseLeave={() => setActiveTooltip(null)}
                        className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-200 p-0.5"
                      >
                        <Info className="w-3.5 h-3.5" />
                      </button>
                      {activeTooltip === 'project-info' && (
                        <div className="absolute left-5 top-0 z-50 w-64 p-2 bg-gray-900 text-white text-[11px] rounded-lg shadow-xl border border-gray-700 pointer-events-none">
                          Tell us what you are scanning and provide project identifiers used across compliance audits and SBOM reports.
                        </div>
                      )}
                    </div>
                  </div>
                  <p className="text-[11px] text-gray-400">
                    {sourceType === 'bulk' ? 'Optional for bulk — each row supplies these' : '* Required fields'}
                  </p>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <ProjectApplicationSelect
                    variant="scan"
                    required={sourceType !== 'bulk'}
                    projectLabel="APPLICATION NAME"
                    applicationLabel="MODULE / SERVICE"
                    projectHint="Registered software application (e.g. PayFlow, Customer Portal)."
                    applicationHint="Module or microservice (e.g. auth-service, payment-api)."
                    value={{ project: selectedProject, application: selectedApplication }}
                    onChange={({ project, application }) => {
                      setSelectedProject(project);
                      setSelectedApplication(application);
                    }}
                  />

                  <div>
                    <label className="block text-xs font-semibold text-gray-700 dark:text-gray-300 mb-1">
                      RELEASE / VERSION {sourceType !== 'bulk' && <span className="text-red-500">*</span>}
                    </label>
                    <input
                      id="release-version-input"
                      type="text"
                      required={sourceType !== 'bulk'}
                      value={releaseVersion}
                      onChange={(e) => setReleaseVersion(e.target.value)}
                      placeholder="e.g. v1.0.0"
                      className="w-full text-xs px-3 py-2 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg text-gray-900 dark:text-white focus:ring-1 focus:ring-blue-500 font-mono"
                    />
                    <p className="text-[10px] text-gray-400 mt-1">Application version or release tag.</p>
                  </div>
                </div>

                {/* Ownership & Development Type */}
                <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4 pt-1">
                  <div>
                    <label className="block text-xs font-semibold text-gray-700 dark:text-gray-300 mb-1">
                      BUSINESS OWNER {sourceType !== 'bulk' && <span className="text-red-500">*</span>}
                    </label>
                    <input
                      type="text"
                      required={sourceType !== 'bulk'}
                      value={businessOwner}
                      onChange={(e) => setBusinessOwner(e.target.value)}
                      placeholder="e.g. Finance Team"
                      className="w-full text-xs px-3 py-2 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg text-gray-900 dark:text-white focus:ring-1 focus:ring-blue-500"
                    />
                    <p className="text-[10px] text-gray-400 mt-1">Department or product team.</p>
                  </div>
                  <div>
                    <label className="block text-xs font-semibold text-gray-700 dark:text-gray-300 mb-1">
                      TECHNICAL OWNER {sourceType !== 'bulk' && <span className="text-red-500">*</span>}
                    </label>
                    <input
                      type="text"
                      required={sourceType !== 'bulk'}
                      value={technicalOwner}
                      onChange={(e) => setTechnicalOwner(e.target.value)}
                      placeholder="e.g. @core-devs / Alice"
                      className="w-full text-xs px-3 py-2 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg text-gray-900 dark:text-white focus:ring-1 focus:ring-blue-500"
                    />
                    <p className="text-[10px] text-gray-400 mt-1">Lead engineer, architect, or team tag.</p>
                  </div>
                  <div>
                    <label className="block text-xs font-semibold text-gray-700 dark:text-gray-300 mb-1">
                      DEVELOPMENT TYPE
                    </label>
                    <select
                      value={developmentType}
                      onChange={(e) => setDevelopmentType(e.target.value as any)}
                      className="w-full text-xs px-3 py-2 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg text-gray-900 dark:text-white focus:ring-1 focus:ring-blue-500"
                    >
                      <option value="In-house">In-house</option>
                      <option value="Outsourced">Outsourced</option>
                      <option value="Vendor">Vendor</option>
                    </select>
                  </div>
                  {developmentType === 'Vendor' ? (
                    <div>
                      <label className="block text-xs font-semibold text-gray-700 dark:text-gray-300 mb-1">
                        VENDOR NAME
                      </label>
                      <input
                        type="text"
                        value={vendorName}
                        onChange={(e) => setVendorName(e.target.value)}
                        placeholder="e.g. Acme Corp / Oracle"
                        className="w-full text-xs px-3 py-2 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg text-gray-900 dark:text-white focus:ring-1 focus:ring-blue-500"
                      />
                    </div>
                  ) : (
                    <div>
                      <label className="block text-xs font-semibold text-gray-700 dark:text-gray-300 mb-1">
                        MODULE TYPE
                      </label>
                      <select
                        value={moduleType}
                        onChange={(e) => setModuleType(e.target.value)}
                        className="w-full text-xs px-3 py-2 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg text-gray-900 dark:text-white focus:ring-1 focus:ring-blue-500"
                      >
                        <option value="Microservice">Microservice</option>
                        <option value="Frontend">Frontend</option>
                        <option value="Backend">Backend</option>
                        <option value="Library">Library</option>
                        <option value="Mobile">Mobile</option>
                        <option value="Other">Other</option>
                      </select>
                    </div>
                  )}
                </div>

                <div className="mt-3 pt-3 border-t border-gray-100 dark:border-gray-800">
                  <label className="block text-xs font-semibold text-gray-700 dark:text-gray-300 mb-1">
                    DESCRIPTION / AUDIT PURPOSE
                  </label>
                  <textarea
                    rows={2}
                    value={description}
                    onChange={(e) => setDescription(e.target.value)}
                    placeholder="Enter scan description or audit context (e.g. Sprint 24 release audit, compliance review)..."
                    className="w-full text-xs px-3 py-2 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg text-gray-900 dark:text-white focus:ring-1 focus:ring-blue-500 resize-none"
                  />
                  <p className="text-[10px] text-gray-400 mt-0.5">Optional context or audit notes for this security scan.</p>
                </div>
              </div>

              {/* SECTION 2: Choose Scan Source */}
              <div className="bg-white dark:bg-[#111827] border border-gray-200 dark:border-gray-800 rounded-xl p-5 shadow-2xs space-y-4">
                <div className="flex items-center justify-between pb-3 border-b border-gray-100 dark:border-gray-800">
                  <div className="flex items-center gap-2">
                    <h2 className="text-sm font-bold text-gray-900 dark:text-white">
                      2. Choose Scan Source
                    </h2>
                    {/* Hover Info Tooltip (Excel Sr 9) */}
                    <div className="relative">
                      <button
                        type="button"
                        onMouseEnter={() => setActiveTooltip('source-info')}
                        onMouseLeave={() => setActiveTooltip(null)}
                        className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-200 p-0.5"
                      >
                        <Info className="w-3.5 h-3.5" />
                      </button>
                      {activeTooltip === 'source-info' && (
                        <div className="absolute left-5 top-0 z-50 w-64 p-2 bg-gray-900 text-white text-[11px] rounded-lg shadow-xl border border-gray-700 pointer-events-none">
                          Select where your source code or project manifests are located: local directories, remote GitHub repositories, or bulk batch scan.
                        </div>
                      )}
                    </div>
                  </div>
                  <p className="text-xs text-gray-500 dark:text-gray-400">
                    Select where your source code or SBOM is located.
                  </p>
                </div>

                {/* 3 Scan Source Cards */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  {/* Card 1: Local Source Directory */}
                  <div
                    onClick={() => setSourceType('local')}
                    onDragOver={(e) => {
                      e.preventDefault();
                      e.stopPropagation();
                      setIsDraggingOverCard(true);
                    }}
                    onDragLeave={() => setIsDraggingOverCard(false)}
                    onDrop={(e) => {
                      e.preventDefault();
                      e.stopPropagation();
                      setIsDraggingOverCard(false);
                      setSourceType('local');
                      if (e.dataTransfer) {
                        acceptLocalDrop(e.dataTransfer);
                      }
                    }}
                    className={`relative rounded-xl p-4 border transition-all cursor-pointer flex flex-col justify-between ${isDraggingOverCard
                      ? 'border-blue-500 bg-blue-50/50 dark:bg-blue-950/40 ring-2 ring-blue-500/50 shadow-md'
                      : sourceType === 'local'
                        ? 'border-sky-500 bg-sky-50/30 dark:bg-sky-950/20 shadow-xs ring-1 ring-sky-500/30'
                        : 'border-gray-200 dark:border-gray-800 hover:border-gray-300'
                      }`}
                  >
                    <div className="flex items-start justify-between">
                      <div className="w-9 h-9 rounded-lg bg-sky-50 dark:bg-sky-950/60 text-sky-600 flex items-center justify-center">
                        <Folder className="w-5 h-5" />
                      </div>
                      <div className={`w-4 h-4 rounded-full border flex items-center justify-center ${sourceType === 'local' ? 'border-sky-600' : 'border-gray-300'}`}>
                        {sourceType === 'local' && <div className="w-2 h-2 rounded-full bg-sky-600" />}
                      </div>
                    </div>
                    <div className="mt-3">
                      <h3 className="text-xs font-bold text-gray-900 dark:text-white uppercase tracking-wider">
                        LOCAL SOURCE DIRECTORY
                      </h3>
                      <p className="text-xs font-semibold text-gray-800 dark:text-gray-200 mt-1">
                        Upload your application source
                      </p>
                      <p className="text-[11px] text-gray-500 dark:text-gray-400 mt-0.5">
                        Scan a project directory from your local machine.
                      </p>
                    </div>
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        setSourceType('local');
                        openLocalUploadModal('files');
                      }}
                      className="mt-4 w-full py-1.5 px-3 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-xs font-semibold cursor-pointer shadow-2xs flex items-center justify-center gap-1.5 transition-colors"
                      title="Upload files or import a folder"
                    >
                      <Upload className="w-3.5 h-3.5 shrink-0" />
                      <span>Upload</span>
                    </button>
                    {(localFolder.length > 0 || localFile) && (
                      <div className="mt-2 flex items-center gap-1.5 text-[11px] text-emerald-600 dark:text-emerald-400 font-medium truncate">
                        <CheckCircle2 className="w-3.5 h-3.5 shrink-0" />
                        <span className="truncate">
                          {localFolder.length > 0
                            ? `${localFolder.length} files (${localFolderStats.totalFolders} folders)`
                            : localFile?.name}
                        </span>
                      </div>
                    )}
                  </div>

                  {/* Card 2: Remote Git Repository (GitHub icon & text only, Excel Sr 3 & Sr 4) */}
                  <div
                    onClick={() => setSourceType('git')}
                    className={`relative rounded-xl p-4 border transition-all cursor-pointer flex flex-col justify-between ${sourceType === 'git'
                      ? 'border-sky-500 bg-sky-50/30 dark:bg-sky-950/20 shadow-xs ring-1 ring-sky-500/30'
                      : 'border-gray-200 dark:border-gray-800 hover:border-gray-300'
                      }`}
                  >
                    <div className="flex items-start justify-between">
                      <div className="w-9 h-9 rounded-lg bg-gray-100 dark:bg-gray-800 text-gray-900 dark:text-white flex items-center justify-center">
                        <Github className="w-5 h-5" />
                      </div>
                      <div className={`w-4 h-4 rounded-full border flex items-center justify-center ${sourceType === 'git' ? 'border-sky-600' : 'border-gray-300'}`}>
                        {sourceType === 'git' && <div className="w-2 h-2 rounded-full bg-sky-600" />}
                      </div>
                    </div>
                    <div className="mt-3">
                      <h3 className="text-xs font-bold text-gray-900 dark:text-white uppercase tracking-wider">
                        REMOTE GIT REPOSITORY
                      </h3>
                      <p className="text-xs font-semibold text-gray-800 dark:text-gray-200 mt-1">
                        Connect remote Git provider
                      </p>
                      <p className="text-[11px] text-gray-500 dark:text-gray-400 mt-0.5">
                        Scan from GitHub repository URL or webhook branch.
                      </p>
                    </div>
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        setSourceType('git');
                      }}
                      className="mt-4 w-full py-1.5 px-3 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-xs font-semibold cursor-pointer shadow-2xs"
                    >
                      Configure Git
                    </button>
                  </div>

                  {/* Card 3: Bulk Spreadsheet Orchestration */}
                  <div
                    onClick={() => setSourceType('bulk')}
                    onDragOver={(e) => {
                      e.preventDefault();
                      e.stopPropagation();
                    }}
                    onDrop={(e) => {
                      e.preventDefault();
                      e.stopPropagation();
                      setSourceType('bulk');
                      const file = e.dataTransfer.files?.[0];
                      if (file) {
                        void handleBulkFile(file);
                      }
                    }}
                    className={`relative rounded-xl p-4 border transition-all cursor-pointer flex flex-col justify-between ${sourceType === 'bulk'
                      ? 'border-sky-500 bg-sky-50/30 dark:bg-sky-950/20 shadow-xs ring-1 ring-sky-500/30'
                      : 'border-gray-200 dark:border-gray-800 hover:border-gray-300'
                      }`}
                  >
                    <div className="flex items-start justify-between">
                      <div className="w-9 h-9 rounded-lg bg-sky-50 dark:bg-sky-950/60 text-sky-600 flex items-center justify-center">
                        <FileSpreadsheet className="w-5 h-5" />
                      </div>
                      <div className={`w-4 h-4 rounded-full border flex items-center justify-center ${sourceType === 'bulk' ? 'border-sky-600' : 'border-gray-300'}`}>
                        {sourceType === 'bulk' && <div className="w-2 h-2 rounded-full bg-sky-600" />}
                      </div>
                    </div>
                    <div className="mt-3">
                      <h3 className="text-xs font-bold text-gray-900 dark:text-white uppercase tracking-wider">
                        BULK SPREADSHEET
                      </h3>
                      <p className="text-xs font-semibold text-gray-800 dark:text-gray-200 mt-1">
                        Multi-project batch scan
                      </p>
                      <p className="text-[11px] text-gray-500 dark:text-gray-400 mt-0.5">
                        Upload CSV / XLSX inventory matrix to scan all apps.
                      </p>
                    </div>
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        setSourceType('bulk');
                        bulkFileInputRef.current?.click();
                      }}
                      className="mt-4 w-full py-1.5 px-3 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-xs font-semibold cursor-pointer shadow-2xs"
                    >
                      Choose File
                    </button>
                  </div>
                </div>

                {/* Source Configuration Detail Panel */}
                <div className="pt-2">
                  {sourceType === 'local' && (
                    <div className="bg-gray-50/70 dark:bg-gray-800/40 border border-gray-200 dark:border-gray-700 rounded-xl p-4 space-y-4">
                      <div
                        onClick={() => openLocalUploadModal('files')}
                        onDragOver={(e) => e.preventDefault()}
                        onDrop={(e) => {
                          e.preventDefault();
                          void acceptLocalDrop(e.dataTransfer);
                        }}
                        className="w-full border-2 border-dashed border-gray-300 dark:border-gray-600 rounded-xl p-8 text-center bg-white dark:bg-gray-800/60 hover:border-blue-400 transition-colors cursor-pointer group"
                      >
                        <Folder className="w-8 h-8 text-blue-500 mx-auto mb-2" />
                        <p className="text-xs font-bold text-gray-900 dark:text-white">
                          Upload one manifest file, or a whole project folder
                        </p>
                        <p className="text-[11px] text-gray-500 dark:text-gray-400 mt-1 max-w-xl mx-auto">
                          Folder mode scans every supported dependency file in the tree (mixed ecosystems in one folder are fine). File mode accepts a single manifest or a .zip archive.
                        </p>
                        <p className="text-[10px] text-gray-400 dark:text-gray-500 mt-1 max-w-xl mx-auto">
                          {SUPPORTED_MANIFEST_HINT}
                        </p>

                        <input
                          ref={folderInputRef}
                          type="file"
                          className="hidden"
                          multiple
                          onChange={(e) => {
                            const items = Array.from(e.target.files || []).map((file) => ({
                              file,
                              relativePath: file.webkitRelativePath || file.name,
                            }));
                            useFolderManifests(items);
                            e.target.value = '';
                          }}
                        />
                        <input
                          ref={fileInputRef}
                          type="file"
                          className="hidden"
                          multiple
                          onChange={(e) => {
                            const picked = Array.from(e.target.files || []);
                            e.target.value = '';
                            if (picked.length === 0) return;
                            if (picked.length === 1) {
                              const file = picked[0];
                              if (file.size === 0) {
                                setLocalFile(null);
                                setLocalFolder([]);
                                setSelectedFolder('');
                                addToast({
                                  type: 'error',
                                  title: 'Empty File',
                                  message: `The file "${file.name}" is empty (0 bytes). Empty files cannot be scanned.`,
                                });
                                return;
                              }
                              setLocalFolder([]);
                              setLocalFile(file);
                              setSelectedFolder(file.name);
                              const name = file.name.toLowerCase();
                              if (name.includes('cyclonedx') || name === 'bom.json' || name === 'bom.xml') {
                                setSbomFormat('CYCLONE DX');
                              } else if (name.includes('spdx')) {
                                setSbomFormat('SPDX');
                              }
                              checkDuplicateForFile(file);
                              return;
                            }
                            const valid = picked.filter((f) => f.size > 0);
                            if (valid.length === 0) {
                              setLocalFile(null);
                              setLocalFolder([]);
                              setSelectedFolder('');
                              addToast({
                                type: 'error',
                                title: 'Empty Files',
                                message: 'All selected files are empty (0 bytes). Empty files cannot be scanned.',
                              });
                              return;
                            }
                            const items: FolderFile[] = valid.map((file) => ({
                              file,
                              relativePath: (file as any).webkitRelativePath || file.name,
                            }));
                            useFolderManifests(items);
                          }}
                        />

                        {/* Selected Folder Summary & Tree Inspector */}
                        {localFolder.length > 0 && (
                          <div className="mt-4 p-4 rounded-xl bg-blue-50/70 dark:bg-blue-950/40 border border-blue-200 dark:border-blue-800/80 text-left space-y-3 animate-in fade-in duration-150">
                            <div className="flex items-start justify-between gap-3">
                              <div className="flex items-start gap-3">
                                <div className="w-10 h-10 rounded-lg bg-blue-600 text-white flex items-center justify-center shrink-0 shadow-xs mt-0.5">
                                  <FolderOpen className="w-5 h-5" />
                                </div>
                                <div>
                                  <div className="flex items-center gap-2 flex-wrap">
                                    <h4 className="text-sm font-bold text-gray-900 dark:text-white font-mono break-all">
                                      {localFolder[0]?.relativePath.replace(/\\/g, '/').split('/')[0] || selectedFolder}
                                    </h4>
                                    <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-100 dark:bg-emerald-950/80 text-emerald-800 dark:text-emerald-300 border border-emerald-300 dark:border-emerald-700 flex items-center gap-1">
                                      <CheckCircle2 className="w-3 h-3" /> All files & folders ready
                                    </span>
                                    <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-blue-100 dark:bg-blue-900/60 text-blue-700 dark:text-blue-300 border border-blue-200 dark:border-blue-700">
                                      {getPrimaryFormatLabel()}
                                    </span>
                                  </div>
                                  <p className="text-xs text-gray-600 dark:text-gray-300 mt-1">
                                    <span className="font-semibold text-gray-900 dark:text-white">{localFolderStats.totalFiles} files</span>
                                    {localFolderStats.totalFolders > 0 && (
                                      <span> across <span className="font-semibold text-gray-900 dark:text-white">{localFolderStats.totalFolders} subfolder{localFolderStats.totalFolders === 1 ? '' : 's'}</span></span>
                                    )}
                                    <span> · {formatBytes(localFolderStats.totalBytes)}</span>
                                  </p>
                                </div>
                              </div>
                              <div className="flex items-center gap-1.5 shrink-0">
                                <button
                                  type="button"
                                  onClick={() => openLocalUploadModal('folder')}
                                  className="px-2.5 py-1 text-xs font-semibold text-blue-600 dark:text-blue-400 hover:bg-blue-100/60 dark:hover:bg-blue-900/40 rounded-lg transition-colors cursor-pointer"
                                  title="Change to another folder"
                                >
                                  Change
                                </button>
                                <button
                                  type="button"
                                  onClick={clearLocalSelection}
                                  className="px-2.5 py-1 text-xs font-semibold text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-950/40 rounded-lg transition-colors cursor-pointer"
                                  title="Remove selection"
                                >
                                  Clear
                                </button>
                              </div>
                            </div>

                            {/* Scope confirmation banner */}
                            <div className="p-2.5 bg-white dark:bg-gray-800/80 rounded-lg border border-blue-100 dark:border-blue-900/30 flex items-center justify-between text-xs flex-wrap gap-2">
                              <div className="flex items-center gap-2">
                                <Check className="w-4 h-4 text-emerald-600 dark:text-emerald-400 shrink-0" />
                                <span className="text-gray-700 dark:text-gray-300 text-[11px]">
                                  System will package and scan <strong>all files and folders</strong> in this directory.
                                </span>
                              </div>
                              {localFolderStats.manifests.length > 0 ? (
                                <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-50 dark:bg-emerald-950/50 text-emerald-700 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800">
                                  {localFolderStats.manifests.length} manifest{localFolderStats.manifests.length === 1 ? '' : 's'} ({localFolderStats.ecosystems.join(', ')})
                                </span>
                              ) : (
                                <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-amber-50 dark:bg-amber-950/50 text-amber-700 dark:text-amber-300 border border-amber-200 dark:border-amber-800">
                                  Generic source scan (all files analyzed)
                                </span>
                              )}
                            </div>

                            {/* Interactive tree/file inspector */}
                            <div className="pt-1">
                              <button
                                type="button"
                                onClick={() => setShowFileTree((prev) => !prev)}
                                className="text-xs font-semibold text-blue-700 dark:text-blue-300 hover:underline flex items-center gap-1.5 cursor-pointer py-0.5"
                              >
                                <ChevronDown className={`w-3.5 h-3.5 transition-transform duration-200 ${showFileTree ? 'rotate-180' : ''}`} />
                                <span>
                                  {showFileTree
                                    ? 'Hide imported files and folders'
                                    : `Inspect all imported files and folders (${localFolderStats.totalFiles} files)`}
                                </span>
                              </button>

                              {showFileTree && (
                                <div className="mt-2 bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-700 p-2.5 space-y-2">
                                  <div className="relative">
                                    <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-gray-400" />
                                    <input
                                      type="text"
                                      value={fileFilter}
                                      onChange={(e) => setFileFilter(e.target.value)}
                                      placeholder="Filter files or subfolders..."
                                      className="w-full text-xs pl-8 pr-3 py-1.5 bg-gray-50 dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-md text-gray-900 dark:text-white focus:outline-none focus:ring-1 focus:ring-blue-500"
                                    />
                                    {fileFilter && (
                                      <button
                                        type="button"
                                        onClick={() => setFileFilter('')}
                                        className="absolute right-2 top-2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-200"
                                      >
                                        <X className="w-3.5 h-3.5" />
                                      </button>
                                    )}
                                  </div>

                                  <div className="max-h-60 overflow-y-auto space-y-0.5 text-xs font-mono divide-y divide-gray-100 dark:divide-gray-800/60 pr-1">
                                    {filteredLocalFiles.length === 0 ? (
                                      <p className="text-center py-4 text-xs text-gray-400 font-sans">
                                        No files matching "{fileFilter}"
                                      </p>
                                    ) : (
                                      filteredLocalFiles.map((item, idx) => {
                                        const rel = item.relativePath.replace(/\\/g, '/');
                                        const isManifest = isManifestRelativePath(rel);
                                        const hasSubdir = rel.includes('/');
                                        return (
                                          <div
                                            key={idx}
                                            className="py-1 px-1.5 flex items-center justify-between hover:bg-gray-50 dark:hover:bg-gray-800/50 rounded transition-colors gap-2"
                                          >
                                            <span className="truncate text-gray-800 dark:text-gray-200 flex items-center gap-1.5 min-w-0">
                                              <span className="text-gray-400 shrink-0">
                                                {hasSubdir ? '📁' : '📄'}
                                              </span>
                                              <span className="truncate">{rel}</span>
                                              {isManifest && (
                                                <span className="text-[10px] bg-emerald-100 dark:bg-emerald-950 text-emerald-700 dark:text-emerald-300 font-sans px-1 rounded shrink-0 font-semibold">
                                                  manifest
                                                </span>
                                              )}
                                            </span>
                                            <span className="text-gray-400 text-[10px] shrink-0 font-sans">
                                              {formatBytes(item.file.size)}
                                            </span>
                                          </div>
                                        );
                                      })
                                    )}
                                  </div>
                                </div>
                              )}
                            </div>
                          </div>
                        )}

                        {/* Selected Single File Summary */}
                        {localFile && (
                          <div className="mt-4 p-4 rounded-xl bg-blue-50/70 dark:bg-blue-950/40 border border-blue-200 dark:border-blue-800/80 text-left space-y-2 animate-in fade-in duration-150">
                            <div className="flex items-start justify-between gap-3">
                              <div className="flex items-start gap-3">
                                <div className="w-10 h-10 rounded-lg bg-blue-600 text-white flex items-center justify-center shrink-0 shadow-xs mt-0.5">
                                  <FileText className="w-5 h-5" />
                                </div>
                                <div>
                                  <div className="flex items-center gap-2 flex-wrap">
                                    <h4 className="text-sm font-bold text-gray-900 dark:text-white font-mono break-all">
                                      {localFile.name}
                                    </h4>
                                    <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-100 dark:bg-emerald-950/80 text-emerald-800 dark:text-emerald-300 border border-emerald-300 dark:border-emerald-700 flex items-center gap-1">
                                      <CheckCircle2 className="w-3 h-3" /> File ready
                                    </span>
                                    <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-blue-100 dark:bg-blue-900/60 text-blue-700 dark:text-blue-300 border border-blue-200 dark:border-blue-700">
                                      {getPrimaryFormatLabel()}
                                    </span>
                                  </div>
                                  <p className="text-xs text-gray-600 dark:text-gray-300 mt-1">
                                    {formatBytes(localFile.size)} · Single file source
                                  </p>
                                </div>
                              </div>
                              <div className="flex items-center gap-1.5 shrink-0">
                                <button
                                  type="button"
                                  onClick={() => openLocalUploadModal('files')}
                                  className="px-2.5 py-1 text-xs font-semibold text-blue-600 dark:text-blue-400 hover:bg-blue-100/60 dark:hover:bg-blue-900/40 rounded-lg transition-colors cursor-pointer"
                                >
                                  Change
                                </button>
                                <button
                                  type="button"
                                  onClick={clearLocalSelection}
                                  className="px-2.5 py-1 text-xs font-semibold text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-950/40 rounded-lg transition-colors cursor-pointer"
                                >
                                  Clear
                                </button>
                              </div>
                            </div>
                          </div>
                        )}
                      </div>

                      <div className="flex items-center gap-2 p-2.5 bg-blue-50 dark:bg-blue-950/40 border border-blue-100 dark:border-blue-900/40 rounded-lg text-xs text-blue-800 dark:text-blue-300">
                        <Info className="w-4 h-4 shrink-0 text-blue-600" />
                        <span>
                          Your source is analyzed to discover dependencies and generate the SBOM. Source code is not displayed in the dashboard.
                        </span>
                      </div>
                    </div>
                  )}

                  {sourceType === 'git' && (
                    <div className="bg-gray-50/70 dark:bg-gray-800/40 border border-gray-200 dark:border-gray-700 rounded-xl p-4 space-y-3">
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        <div>
                          <label className="block text-xs font-semibold text-gray-700 dark:text-gray-300 mb-1">
                            GITHUB REPOSITORY URL
                          </label>
                          <input
                            type="url"
                            value={gitUrl}
                            onChange={(e) => setGitUrl(e.target.value)}
                            placeholder="https://github.com/organization/payments-api"
                            className="w-full text-xs px-3 py-2 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg text-gray-900 dark:text-white"
                          />
                        </div>
                        <div>
                          <label className="block text-xs font-semibold text-gray-700 dark:text-gray-300 mb-1">
                            BRANCH OR COMMIT TAG
                          </label>
                          <input
                            type="text"
                            value={gitBranch}
                            onChange={(e) => setGitBranch(e.target.value)}
                            placeholder="main"
                            className="w-full text-xs px-3 py-2 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg text-gray-900 dark:text-white"
                          />
                        </div>
                      </div>
                      <div>
                        <label className="block text-xs font-semibold text-gray-700 dark:text-gray-300 mb-1">
                          GITHUB PERSONAL ACCESS TOKEN <span className="text-gray-400 font-normal">(Required for private repos)</span>
                        </label>
                        <input
                          type="password"
                          value={gitToken}
                          onChange={(e) => setGitToken(e.target.value)}
                          placeholder="ghp_xxxxxxxxxxxxxxxxxxxx"
                          className="w-full text-xs px-3 py-2 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg text-gray-900 dark:text-white"
                        />
                      </div>
                    </div>
                  )}

                  {sourceType === 'bulk' && (
                    <div className="bg-gray-50/70 dark:bg-gray-800/40 border border-gray-200 dark:border-gray-700 rounded-xl p-4 space-y-4">
                      {/* Header bar with mode switcher and template download */}
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 pb-3 border-b border-gray-200 dark:border-gray-700">
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-bold text-gray-900 dark:text-white uppercase tracking-wider">
                            Batch Inventory Matrix
                          </span>
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-sky-50 dark:bg-sky-950/60 text-sky-700 dark:text-sky-300 border border-sky-200 dark:border-sky-800">
                            .CSV / .XLSX
                          </span>
                        </div>

                        <div className="flex items-center gap-2 flex-wrap">
                          <button
                            type="button"
                            onClick={handleDownloadSampleCsv}
                            className="px-2.5 py-1 text-xs font-semibold text-blue-600 hover:text-blue-700 dark:text-blue-400 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-750 flex items-center gap-1.5 shadow-2xs cursor-pointer transition-colors"
                          >
                            <Download className="w-3.5 h-3.5" />
                            Download Template (.CSV)
                          </button>

                          <div className="flex items-center bg-gray-200 dark:bg-gray-700 p-0.5 rounded-lg text-[11px]">
                            <button
                              type="button"
                              onClick={() => setBulkMode('file')}
                              className={`px-2.5 py-0.5 rounded font-medium cursor-pointer transition-colors ${bulkMode === 'file'
                                ? 'bg-white dark:bg-gray-800 text-blue-600 dark:text-blue-400 shadow-2xs font-bold'
                                : 'text-gray-600 dark:text-gray-300 hover:text-gray-900'
                                }`}
                            >
                              Spreadsheet File
                            </button>
                            <button
                              type="button"
                              onClick={() => setBulkMode('manual')}
                              className={`px-2.5 py-0.5 rounded font-medium cursor-pointer transition-colors ${bulkMode === 'manual'
                                ? 'bg-white dark:bg-gray-800 text-blue-600 dark:text-blue-400 shadow-2xs font-bold'
                                : 'text-gray-600 dark:text-gray-300 hover:text-gray-900'
                                }`}
                            >
                              Manual List
                            </button>
                          </div>
                        </div>
                      </div>

                      {bulkMode === 'file' ? (
                        <div className="space-y-4">
                          {/* Dropzone & Upload Button */}
                          <div
                            onClick={() => bulkFileInputRef.current?.click()}
                            onDragOver={(e) => {
                              e.preventDefault();
                              e.stopPropagation();
                            }}
                            onDrop={(e) => {
                              e.preventDefault();
                              e.stopPropagation();
                              const file = e.dataTransfer.files?.[0];
                              if (file) {
                                void handleBulkFile(file);
                              }
                            }}
                            className="border-2 border-dashed border-gray-300 dark:border-gray-600 rounded-xl p-5 text-center bg-white dark:bg-gray-800/60 hover:border-blue-400 dark:hover:border-blue-500 transition-colors cursor-pointer group"
                          >
                            <div className="w-12 h-12 rounded-xl bg-blue-50 dark:bg-blue-950/60 text-blue-600 flex items-center justify-center mx-auto mb-2 group-hover:scale-105 transition-transform">
                              <FileSpreadsheet className="w-6 h-6" />
                            </div>
                            <p className="text-xs font-bold text-gray-900 dark:text-white">
                              Upload Bulk Inventory Spreadsheet (.CSV, .XLSX, .XLS)
                            </p>
                            <p className="text-xs text-blue-600 font-semibold hover:underline mt-0.5">
                              Drag and drop file here, or browse files
                            </p>
                            <p className="text-[10px] text-gray-400 mt-1.5">
                              Required columns: project_name, application_name, version, repository_url
                            </p>
                            <p className="text-[10px] text-gray-400 mt-1">
                              The same GitHub repository and branch is one project. The first row is scanned. Later copies and invalid rows are skipped, and the rest of the file still runs.
                            </p>
                            <input
                              ref={bulkFileInputRef}
                              type="file"
                              accept=".csv,.xlsx,.xls,text/csv,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet,application/vnd.ms-excel"
                              className="hidden"
                              onChange={handleBulkFileUpload}
                            />
                          </div>

                          {/* Selected File Card & Verification Status */}
                          {/* <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-xl p-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-3 shadow-2xs">
                            <div className="flex items-center gap-3">
                              <div className="w-9 h-9 rounded-lg bg-emerald-50 dark:bg-emerald-950/60 text-emerald-600 border border-emerald-200 dark:border-emerald-800/50 flex items-center justify-center shrink-0">
                                <FileSpreadsheet className="w-5 h-5" />
                              </div>
                              <div>
                                <div className="flex items-center gap-2">
                                  <span className="text-xs font-bold text-gray-900 dark:text-white font-mono">
                                    {bulkFile.name}
                                  </span>
                                  <span className={`px-1.5 py-0.2 rounded text-[10px] font-bold ${bulkFileError || bulkProjects.some((row) => row.rowStatus && row.rowStatus !== 'ready')
                                    ? 'bg-amber-50 text-amber-700 dark:bg-amber-950/60 dark:text-amber-300'
                                    : 'bg-emerald-50 text-emerald-700 dark:bg-emerald-950/60 dark:text-emerald-300'
                                    }`}>
                                    {bulkFileError ? 'Invalid file' : bulkProjects.some((row) => row.rowStatus && row.rowStatus !== 'ready') ? 'Needs review' : 'Verified'}
                                  </span>
                                </div>
                                <span className="text-[11px] text-gray-500">
                                  {bulkFile.size} • {bulkProjects.length} Microservices Detected • {bulkFile.uploadedAt}
                                </span>
                              </div>
                            </div>

                            <div className="flex items-center gap-2 self-end sm:self-center">
                              <button
                                type="button"
                                onClick={() => bulkFileInputRef.current?.click()}
                                className="px-2.5 py-1 text-xs font-semibold text-gray-700 dark:text-gray-300 bg-gray-50 dark:bg-gray-750 hover:bg-gray-100 dark:hover:bg-gray-700 border border-gray-200 dark:border-gray-600 rounded-lg cursor-pointer transition-colors"
                              >
                                Replace File
                              </button>
                            </div>
                          </div> */}

                          {/* Parsed Projects Matrix Table Preview */}
                          <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-xl overflow-hidden shadow-2xs">
                            <div className="px-3.5 py-2.5 bg-gray-50/80 dark:bg-gray-750/50 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between">
                              <span className="text-xs font-bold text-gray-800 dark:text-gray-200">
                                Parsed Projects Matrix ({bulkProjects.length})
                              </span>
                              <span className="text-[11px] text-gray-400">
                                {bulkProjects.filter((row) => !row.rowStatus || row.rowStatus === 'ready').length} ready
                                {' · '}
                                {bulkProjects.filter((row) => row.rowStatus === 'duplicate').length} duplicate
                                {' · '}
                                {bulkProjects.filter((row) => row.rowStatus === 'invalid').length} invalid
                              </span>
                            </div>

                            <div className="overflow-x-auto">
                              <table className="w-full text-left text-xs">
                                <thead>
                                  <tr className="border-b border-gray-200 dark:border-gray-700 text-gray-500 text-[11px] uppercase tracking-wider bg-gray-50/40 dark:bg-gray-800/40">
                                    <th className="p-2.5 pl-3.5 font-bold">#</th>
                                    <th className="p-2.5 font-bold">Project Name</th>
                                    <th className="p-2.5 font-bold">Repository / Source Path</th>
                                    <th className="p-2.5 font-bold">Branch / Tag</th>
                                    <th className="p-2.5 font-bold">Ecosystem</th>
                                    <th className="p-2.5 pr-3.5 font-bold text-right">Status</th>
                                  </tr>
                                </thead>
                                <tbody className="divide-y divide-gray-100 dark:divide-gray-800 font-medium">
                                  {bulkProjects.map((row, index) => (
                                    <tr key={row.id} className="hover:bg-gray-50/50 dark:hover:bg-gray-750/30">
                                      <td className="p-2.5 pl-3.5 text-gray-400 font-mono text-[11px]">{row.rowNumber || index + 1}</td>
                                      <td className="p-2.5 font-bold text-gray-900 dark:text-white">{row.project}</td>
                                      <td className="p-2.5 font-mono text-[11px] text-gray-600 dark:text-gray-300 truncate max-w-[220px]" title={row.rowMessage || row.source}>
                                        {row.source}
                                      </td>
                                      <td className="p-2.5 font-mono text-[11px] text-gray-500">{row.branch}</td>
                                      <td className="p-2.5">
                                        <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300">
                                          {row.ecosystem}
                                        </span>
                                      </td>
                                      <td className="p-2.5 pr-3.5 text-right">
                                        {row.rowStatus === 'duplicate' ? (
                                          <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-amber-600 dark:text-amber-400" title={row.rowMessage}>
                                            <AlertTriangle className="w-3.5 h-3.5" />
                                            Duplicate
                                          </span>
                                        ) : row.rowStatus === 'invalid' ? (
                                          <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-red-600 dark:text-red-400" title={row.rowMessage}>
                                            <AlertTriangle className="w-3.5 h-3.5" />
                                            Invalid
                                          </span>
                                        ) : (
                                          <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-emerald-600 dark:text-emerald-400" title={row.rowMessage}>
                                            <CheckCircle2 className="w-3.5 h-3.5" />
                                            Ready
                                          </span>
                                        )}
                                      </td>
                                    </tr>
                                  ))}
                                </tbody>
                              </table>
                            </div>
                          </div>
                        </div>
                      ) : (
                        /* Manual Textarea Fallback */
                        <div className="space-y-2">
                          <label className="block text-xs font-semibold text-gray-700 dark:text-gray-300">
                            REPOSITORIES OR DIRECTORIES TO BATCH SCAN (One per line)
                          </label>
                          <textarea
                            rows={4}
                            value={bulkScanList}
                            onChange={(e) => setBulkScanList(e.target.value)}
                            className="w-full text-xs px-3 py-2 font-mono bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg text-gray-900 dark:text-white focus:ring-1 focus:ring-blue-500 resize-none"
                            placeholder="https://github.com/expressjs/express&#10;https://github.com/pallets/flask"
                          />
                          <p className="text-[11px] text-gray-500">
                            Enter Git repository URLs or absolute local folder paths separated by new lines.
                          </p>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              </div>



              {/* Bottom Action Bar: Cancel and Launch Scan (Excel Sr 6) */}
              <div className="flex items-center justify-between pt-4 border-t border-gray-200 dark:border-gray-800">
                <button
                  type="button"
                  onClick={() => setTab('table')}
                  className="px-4 py-2 border border-gray-300 dark:border-gray-700 rounded-lg text-xs font-semibold text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-800 cursor-pointer"
                >
                  Cancel
                </button>

                <button
                  type="submit"
                  className="px-6 py-2.5 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-xs font-bold flex items-center gap-2 shadow-sm cursor-pointer"
                >
                  <span>Launch Scan</span>
                  <ArrowRight className="w-4 h-4" />
                </button>
              </div>
            </form>
          ) : (
            /* STAGE 2: REVIEW PAGE (Excel Sr 5 & Sr 8) */
            <div className="space-y-6">
              <div className="bg-white dark:bg-[#111827] border border-gray-200 dark:border-gray-800 rounded-xl p-6 shadow-2xs space-y-6">
                <div className="flex items-center justify-between pb-4 border-b border-gray-100 dark:border-gray-800">
                  <div>
                    <h2 className="text-sm font-bold text-gray-900 dark:text-white">
                      Review Scan Configuration
                    </h2>
                    <p className="text-xs text-gray-500 dark:text-gray-400 mt-0.5">
                      Verify the parameters below before initiating SBOM generation and supply chain analysis.
                    </p>
                  </div>
                  <span className="px-2.5 py-1 bg-blue-50 dark:bg-blue-950/60 text-blue-700 dark:text-blue-300 text-xs font-bold rounded-lg">
                    Ready to Launch
                  </span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div className="space-y-3">
                    <h3 className="text-xs font-bold uppercase tracking-wider text-gray-500 dark:text-gray-400">
                      Project Details
                    </h3>
                    <div className="bg-gray-50/70 dark:bg-gray-800/40 rounded-xl p-4 border border-gray-200 dark:border-gray-700 space-y-2.5 text-xs">
                      {sourceType === 'bulk' ? (
                        <>
                          <div className="flex justify-between">
                            <span className="text-gray-500">Project Name:</span>
                            <span className="font-bold text-gray-900 dark:text-white">{projectName.trim() || 'From file'}</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-gray-500">Application / Service:</span>
                            <span className="font-semibold text-gray-900 dark:text-white">{appService.trim() || 'From file'}</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-gray-500">Release Version:</span>
                            <span className="font-mono font-semibold text-gray-900 dark:text-white">{releaseVersion.trim() || 'From file'}</span>
                          </div>
                          <p className="text-gray-500 pt-2 border-t border-gray-200 dark:border-gray-700">Each ready row is its own scan. Duplicate projects and invalid rows are skipped.</p>
                          {bulkProjects.length > 0 && (
                            <div className="space-y-1.5 max-h-40 overflow-y-auto">
                              {bulkProjects.map((row) => (
                                <div key={row.id} className="flex justify-between gap-3">
                                  <span className="font-semibold text-gray-900 dark:text-white truncate">{row.project}</span>
                                  <span className={`truncate ${row.rowStatus === 'invalid' ? 'text-red-600' : row.rowStatus === 'duplicate' ? 'text-amber-600' : 'text-gray-500'}`}>
                                    {row.rowStatus === 'duplicate' ? 'Duplicate' : row.rowStatus === 'invalid' ? 'Invalid' : `${row.name} · ${row.version || 'UNKNOWN'}`}
                                  </span>
                                </div>
                              ))}
                            </div>
                          )}
                        </>
                      ) : (
                        <>
                          <div className="flex justify-between">
                            <span className="text-gray-500">Project Name:</span>
                            <span className="font-bold text-gray-900 dark:text-white">{projectName}</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-gray-500">Application / Service:</span>
                            <span className="font-semibold text-gray-900 dark:text-white">{appService}</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-gray-500">Release Version:</span>
                            <span className="font-mono font-semibold text-gray-900 dark:text-white">{releaseVersion}</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-gray-500">Business Owner:</span>
                            <span className="font-semibold text-gray-900 dark:text-white">{businessOwner}</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-gray-500">Technical Owner:</span>
                            <span className="font-semibold text-gray-900 dark:text-white">{technicalOwner}</span>
                          </div>
                          <div className="pt-2 border-t border-gray-200 dark:border-gray-700">
                            <span className="text-gray-500 block mb-1">Description:</span>
                            <p className="text-gray-700 dark:text-gray-300 italic">{description || 'No description provided'}</p>
                          </div>
                        </>
                      )}
                    </div>
                  </div>

                  <div className="space-y-3">
                    <h3 className="text-xs font-bold uppercase tracking-wider text-gray-500 dark:text-gray-400">
                      Scan Source & Engine
                    </h3>
                    <div className="bg-gray-50/70 dark:bg-gray-800/40 rounded-xl p-4 border border-gray-200 dark:border-gray-700 space-y-2.5 text-xs">
                      <div className="flex justify-between">
                        <span className="text-gray-500">Source Type:</span>
                        <span className="font-bold text-gray-900 dark:text-white capitalize">
                          {sourceType === 'local' ? 'Local Source Directory' : sourceType === 'git' ? 'Remote Git (GitHub)' : 'Bulk Spreadsheet Matrix'}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-500">Target Location:</span>
                        <span className="font-mono text-gray-900 dark:text-white truncate max-w-[220px]">
                          {sourceType === 'local' ? selectedFolder : sourceType === 'git' ? gitUrl : `${bulkFile.name} (${bulkProjects.length} Projects)`}
                        </span>
                      </div>
                      {sourceType === 'local' && localFolder.length > 0 && (
                        <div className="flex justify-between items-center text-xs">
                          <span className="text-gray-500">Import Scope:</span>
                          <span className="font-medium text-emerald-600 dark:text-emerald-400 flex items-center gap-1">
                            <CheckCircle2 className="w-3.5 h-3.5" />
                            All {localFolderStats.totalFiles} files across {localFolderStats.totalFolders} folders
                          </span>
                        </div>
                      )}
                      <div className="flex justify-between items-center">
                        <span className="text-gray-500">Primary Format:</span>
                        <select
                          value={sbomFormat}
                          onChange={(e) => setSbomFormat(e.target.value as 'SPDX' | 'CYCLONE DX')}
                          className="font-bold text-blue-600 dark:text-blue-400 bg-transparent text-xs cursor-pointer border border-blue-200 dark:border-blue-800/80 rounded px-2 py-0.5 hover:border-blue-400 focus:outline-none focus:ring-1 focus:ring-blue-500 transition-colors"
                        >
                          <option value="SPDX" className="text-gray-900 dark:text-white bg-white dark:bg-gray-800">SPDX</option>
                          <option value="CYCLONE DX" className="text-gray-900 dark:text-white bg-white dark:bg-gray-800">CYCLONE DX</option>
                        </select>
                      </div>
                    </div>
                  </div>
                </div>

                <div className="bg-emerald-50/50 dark:bg-emerald-950/20 border border-emerald-200 dark:border-emerald-800/40 rounded-xl p-4 flex items-center justify-between text-xs">
                  <div className="flex items-center gap-3">
                    <div className="w-8 h-8 rounded-lg bg-emerald-100 dark:bg-emerald-900/60 text-emerald-600 flex items-center justify-center">
                      <CheckCircle2 className="w-4 h-4" />
                    </div>
                    <div>
                      <p className="font-bold text-gray-900 dark:text-white">Scan engine initialized and ready</p>
                      <p className="text-gray-500 dark:text-gray-400 text-[11px]">
                        Estimated duration: ~18 seconds. Lockfile resolution, CVE matching and attestation will execute.
                      </p>
                    </div>
                  </div>
                  <span className="font-mono font-bold text-emerald-600 dark:text-emerald-400">~18s</span>
                </div>
              </div>

              {/* Bottom Action Bar: Back and Prominent Launch Scan (Excel Sr 8) */}
              <div className="flex items-center justify-between pt-4 border-t border-gray-200 dark:border-gray-800">
                <button
                  type="button"
                  onClick={() => setNewScanStep('input')}
                  className="px-4 py-2 border border-gray-300 dark:border-gray-700 rounded-lg text-xs font-semibold text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-800 cursor-pointer"
                >
                  ← Back to Configuration
                </button>

                <button
                  type="button"
                  disabled={isSubmitting}
                  onClick={handleFinalLaunchScan}
                  className="px-8 py-3 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white rounded-lg text-sm font-bold flex items-center gap-2 shadow-md cursor-pointer transition-colors"
                >
                  {isSubmitting ? (
                    <>
                      <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                      <span>Dispatching Scan...</span>
                    </>
                  ) : (
                    <>
                      <Play className="w-4 h-4 fill-white" />
                      <span>Launch Scan</span>
                    </>
                  )}
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ========================================================================= */}
      {/* 2. LIVE JOBS SUB-PAGE (Workspace UI Spec Section 11)                      */}
      {/* ========================================================================= */}
      {activeTab === 'live' && (
        <LiveScanMonitorTab
          waitingScans={waitingScans}
          activeScan={activeScan}
          pipelineScan={pipelineScan}
          bulkChildren={bulkChildren}
          scanFailed={scanFailed}
          now={now}
          cancellingId={cancellingId}
          rescanningId={rescanningId}
          canCancel={canCancel}
          canRescan={canRescan}
          onGoToLaunchScan={goToLaunchScan}
          onCancel={handleCancel}
          onRescan={handleRescan}
          onSelectScan={setSelectedScanId}
        />
      )}

      {/* ========================================================================= */}
      {/* 3. SCAN HISTORY SUB-PAGE (Workspace UI Spec Section 12)                    */}
      {/* ========================================================================= */}
      {activeTab === 'history' && (
        <ScanHistoryTab
          historySearch={historySearch}
          onHistorySearchChange={setHistorySearch}
          historyStatusFilter={historyStatusFilter}
          onHistoryStatusFilterChange={setHistoryStatusFilter}
          filteredHistory={filteredHistory}
          rescanningId={rescanningId}
          onSelectScan={setSelectedScanId}
          onExport={exportSBOM}
          onRescan={handleRescan}
          onToggleLifecycle={(scan, newStatus) => updateApplicationLifecycle(scan.targetProject, newStatus)}
        />
      )}

      {/* ========================================================================= */}
      {/* 4. SCHEDULED SCANS SUB-PAGE (Workspace UI Spec Section 13)                */}
      {/* ========================================================================= */}
      {activeTab === 'schedules' && (
        <ScanSchedulesTab
          schedulesList={schedulesList}
          onToggleSchedule={toggleSchedule}
          onRunNow={(sched) => {
            addToast({
              type: 'info',
              title: 'Schedule Dispatched',
              message: `Triggered immediate run of "${sched.name}".`,
            });
            setTab('live');
          }}
          onDeleteSchedule={(id) => {
            setSchedulesList((prev) => prev.filter((s) => s.id !== id));
            addToast({ type: 'info', title: 'Schedule Deleted', message: `Removed schedule.` });
          }}
          onOpenCreateModal={() => setCreateScheduleModalOpen(true)}
        />
      )}

      {selectedHistoryScan && (
        <ScanResultDetails
          job={selectedHistoryScan}
          related={scansHistory.filter((scan) => selectedHistoryScan.bulkId && scan.bulkId === selectedHistoryScan.bulkId && !scan.isBulkAggregate)}
          now={now}
          cancelling={cancellingId === selectedHistoryScan.id}
          rescanning={rescanningId === selectedHistoryScan.id}
          canCancel={canCancel(selectedHistoryScan.status)}
          canRescan={canRescan(selectedHistoryScan.status)}
          onClose={() => setSelectedScanId(null)}
          onCancel={handleCancel}
          onRescan={handleRescan}
          onOpenScan={setSelectedScanId}
          onExport={(format, scanId) => exportSBOM(format, scanId)}
        />
      )}

      <CreateScheduleModal
        isOpen={createScheduleModalOpen}
        onClose={() => setCreateScheduleModalOpen(false)}
        onSubmit={handleCreateSchedule}
        newSchedName={newSchedName}
        onNewSchedNameChange={setNewSchedName}
        newSchedProject={newSchedProject}
        onNewSchedProjectChange={setNewSchedProject}
        newSchedDate={newSchedDate}
        onNewSchedDateChange={setNewSchedDate}
        newSchedTime={newSchedTime}
        onNewSchedTimeChange={setNewSchedTime}
        newSchedTimezone={newSchedTimezone}
        onNewSchedTimezoneChange={setNewSchedTimezone}
        newSchedFreq={newSchedFreq}
        onNewSchedFreqChange={setNewSchedFreq}
      />

      {/* Local Source Upload Tabbed Modal (Matches User Reference Image) */}
      {localUploadModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4 animate-in fade-in duration-150">
          <div className="bg-white dark:bg-[#111827] rounded-xl max-w-xl w-full shadow-2xl border border-gray-200 dark:border-gray-800 overflow-hidden">
            {/* Tab Bar Header */}
            <div className="flex items-center justify-between border-b border-gray-200 dark:border-gray-800 px-6 pt-3.5 bg-gray-50/50 dark:bg-gray-900/40">
              <div className="flex items-center gap-8">
                <button
                  type="button"
                  onClick={() => setLocalModalTab('files')}
                  className={`pb-3 text-sm font-bold transition-all relative cursor-pointer ${localModalTab === 'files'
                    ? 'text-blue-600 dark:text-blue-400'
                    : 'text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300'
                    }`}
                >
                  Upload Files
                  {localModalTab === 'files' && (
                    <span className="absolute bottom-0 left-0 right-0 h-0.5 bg-blue-600 dark:bg-blue-400" />
                  )}
                </button>
                <button
                  type="button"
                  onClick={() => setLocalModalTab('folder')}
                  className={`pb-3 text-sm font-bold transition-all relative cursor-pointer ${localModalTab === 'folder'
                    ? 'text-blue-600 dark:text-blue-400'
                    : 'text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300'
                    }`}
                >
                  Import Folder
                  {localModalTab === 'folder' && (
                    <span className="absolute bottom-0 left-0 right-0 h-0.5 bg-blue-600 dark:bg-blue-400" />
                  )}
                </button>
              </div>
              <button
                type="button"
                onClick={() => setLocalUploadModalOpen(false)}
                className="pb-3 text-gray-400 hover:text-gray-600 dark:hover:text-gray-200 cursor-pointer"
                title="Close"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Modal Body */}
            <div className="p-6 space-y-4">
              {/* Dashed Dropzone */}
              <div
                onClick={() => {
                  if (localModalTab === 'files') {
                    modalFileInputRef.current?.click();
                  } else {
                    modalFolderInputRef.current?.click();
                  }
                }}
                onDragOver={(e) => {
                  e.preventDefault();
                  e.stopPropagation();
                }}
                onDrop={async (e) => {
                  e.preventDefault();
                  e.stopPropagation();
                  if (localModalTab === 'files') {
                    const file = e.dataTransfer.files?.[0];
                    if (!file) return;
                    if (file.size === 0) {
                      addToast({
                        type: 'error',
                        title: 'Empty File',
                        message: `The file "${file.name}" is empty (0 bytes). Empty files cannot be scanned.`,
                      });
                      return;
                    }
                    setPendingLocalFile(file);
                    setPendingLocalFolder([]);
                  } else {
                    const items = await filesFromDataTransfer(e.dataTransfer);
                    if (!items || items.length === 0 || items.every((f) => f.file.size === 0)) {
                      addToast({
                        type: 'error',
                        title: 'Empty Folder',
                        message: 'The selected folder contains no files or only empty files (0 bytes). Empty folders cannot be scanned.',
                      });
                      return;
                    }
                    setPendingLocalFolder(items);
                    setPendingLocalFile(null);
                  }
                }}
                className="border border-dashed border-gray-300 dark:border-gray-600 rounded-lg p-6 sm:p-7 text-center bg-gray-50/50 dark:bg-gray-800/30 hover:border-blue-500 dark:hover:border-blue-400 transition-colors cursor-pointer group"
              >
                <div className="w-10 h-10 rounded-lg bg-blue-50 dark:bg-blue-950/60 text-blue-600 dark:text-blue-400 flex items-center justify-center mx-auto mb-2.5 group-hover:scale-105 transition-transform">
                  {localModalTab === 'files' ? (
                    <FileText className="w-5 h-5" />
                  ) : (
                    <Folder className="w-5 h-5" />
                  )}
                </div>
                <p className="text-xs font-bold text-blue-600 dark:text-blue-400 group-hover:underline">
                  {localModalTab === 'files' ? 'Drag & Drop or Browse files.' : 'Drag & Drop or Browse folder.'}
                </p>
                <p className="text-[11px] text-gray-500 dark:text-gray-400 mt-1">
                  Max size limit 400 MB
                </p>
                <p className="text-[11px] text-gray-400 dark:text-gray-500 mt-0.5">
                  {localModalTab === 'files'
                    ? 'Max no of file(s) 25 · Supports package manifests, .zip, .tar.gz, CycloneDX, SPDX'
                    : 'Imports all files & subfolders within the selected directory'}
                </p>

                <input
                  ref={modalFileInputRef}
                  type="file"
                  multiple={false}
                  className="hidden"
                  onChange={(e) => {
                    const file = e.target.files?.[0];
                    e.target.value = '';
                    if (!file) return;
                    if (file.size === 0) {
                      addToast({
                        type: 'error',
                        title: 'Empty File',
                        message: `The file "${file.name}" is empty (0 bytes). Empty files cannot be scanned.`,
                      });
                      return;
                    }
                    setPendingLocalFile(file);
                    setPendingLocalFolder([]);
                  }}
                />
                <input
                  ref={modalFolderInputRef}
                  type="file"
                  multiple
                  className="hidden"
                  // @ts-expect-error webkitdirectory standard folder attribute
                  webkitdirectory=""
                  directory=""
                  onChange={(e) => {
                    const picked = Array.from(e.target.files || []);
                    e.target.value = '';
                    if (picked.length === 0) return;
                    const items: FolderFile[] = picked.map((file) => ({
                      file,
                      relativePath: (file as any).webkitRelativePath || file.name,
                    }));
                    const nonSkipped = items.filter((item) => {
                      const rel = item.relativePath.replace(/\\/g, '/');
                      return rel !== '' && !isInsideSkippedDir(rel);
                    });
                    const finalItems = nonSkipped.length > 0 ? nonSkipped : items;
                    if (finalItems.length === 0 || finalItems.every((item) => item.file.size === 0)) {
                      addToast({
                        type: 'error',
                        title: 'Empty Folder',
                        message: 'The selected folder contains no files or only empty files (0 bytes). Empty folders cannot be scanned.',
                      });
                      return;
                    }
                    setPendingLocalFolder(finalItems);
                    setPendingLocalFile(null);
                  }}
                />
              </div>

              {/* Preview Section */}
              <div className="space-y-1.5 pt-1">
                <label className="block text-xs font-semibold text-gray-700 dark:text-gray-300">
                  Preview:
                </label>
                {localModalTab === 'files' && pendingLocalFile ? (
                  <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-md border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-800 text-xs text-gray-800 dark:text-gray-200 shadow-2xs">
                    <FileText className="w-3.5 h-3.5 text-blue-600 dark:text-blue-400" />
                    <span className="font-medium max-w-xs truncate">{pendingLocalFile.name}</span>
                    <span className="text-[10px] text-gray-400">({formatBytes(pendingLocalFile.size)})</span>
                    <button
                      type="button"
                      onClick={() => setPendingLocalFile(null)}
                      className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-200 rounded-full cursor-pointer ml-1"
                      title="Remove file"
                    >
                      <X className="w-3.5 h-3.5" />
                    </button>
                  </div>
                ) : localModalTab === 'folder' && pendingLocalFolder.length > 0 ? (
                  <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-md border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-800 text-xs text-gray-800 dark:text-gray-200 shadow-2xs">
                    <Folder className="w-3.5 h-3.5 text-blue-600 dark:text-blue-400" />
                    <span className="font-medium max-w-xs truncate">
                      {pendingLocalFolder[0]?.relativePath.replace(/\\/g, '/').split('/')[0] || 'Project Folder'}
                    </span>
                    <span className="text-[10px] text-gray-400">
                      ({pendingLocalFolder.length} files, {formatBytes(pendingLocalFolder.reduce((acc, f) => acc + f.file.size, 0))})
                    </span>
                    <button
                      type="button"
                      onClick={() => setPendingLocalFolder([])}
                      className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-200 rounded-full cursor-pointer ml-1"
                      title="Remove folder"
                    >
                      <X className="w-3.5 h-3.5" />
                    </button>
                  </div>
                ) : (
                  <div className="text-xs text-gray-400 italic py-1">
                    No {localModalTab === 'files' ? 'file' : 'folder'} selected yet
                  </div>
                )}
              </div>

              {/* Modal Footer Buttons */}
              <div className="flex items-center justify-end gap-2.5 pt-3 border-t border-gray-100 dark:border-gray-800">
                <button
                  type="button"
                  onClick={() => setLocalUploadModalOpen(false)}
                  className="px-4 py-1.5 rounded-md border border-gray-300 dark:border-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-800 text-xs font-medium cursor-pointer transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={() => {
                    if (localModalTab === 'files') {
                      if (!pendingLocalFile) {
                        addToast({
                          type: 'warning',
                          title: 'File Required',
                          message: 'Please browse or drag and drop a file before uploading.',
                        });
                        return;
                      }
                      if (pendingLocalFile.size === 0) {
                        addToast({
                          type: 'error',
                          title: 'Empty File',
                          message: `The file "${pendingLocalFile.name}" is empty (0 bytes). Empty files cannot be scanned.`,
                        });
                        return;
                      }
                      setLocalFolder([]);
                      setLocalFile(pendingLocalFile);
                      setSelectedFolder(pendingLocalFile.name);
                      const name = pendingLocalFile.name.toLowerCase();
                      if (name.includes('cyclonedx') || name === 'bom.json' || name === 'bom.xml') {
                        setSbomFormat('CYCLONE DX');
                      } else if (name.includes('spdx')) {
                        setSbomFormat('SPDX');
                      }
                      setLocalUploadModalOpen(false);
                      checkDuplicateForFile(pendingLocalFile);
                      addToast({
                        type: 'success',
                        title: 'File Ready',
                        message: `Loaded ${pendingLocalFile.name} (${formatBytes(pendingLocalFile.size)}) for local scan.`,
                      });
                    } else {
                      if (pendingLocalFolder.length === 0) {
                        addToast({
                          type: 'warning',
                          title: 'Folder Required',
                          message: 'Please browse or drag and drop a project folder before uploading.',
                        });
                        return;
                      }
                      if (pendingLocalFolder.every((f) => f.file.size === 0)) {
                        addToast({
                          type: 'error',
                          title: 'Empty Folder',
                          message: 'The selected folder contains no files or only empty files (0 bytes). Empty folders cannot be scanned.',
                        });
                        return;
                      }
                      useFolderManifests(pendingLocalFolder);
                      setLocalUploadModalOpen(false);
                      addToast({
                        type: 'success',
                        title: 'Folder Ready',
                        message: `Imported folder with ${pendingLocalFolder.length} files for local scan.`,
                      });
                    }
                  }}
                  className="px-5 py-1.5 rounded-md bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold cursor-pointer shadow-sm shadow-blue-500/20 transition-colors"
                >
                  Upload
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Rescan Options Modal (Scenario 10) */}
      {rescanTargetJob && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 backdrop-blur-xs animate-in fade-in duration-150">
          <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-xl shadow-2xl w-full max-w-lg overflow-hidden flex flex-col">
            <div className="flex items-center justify-between px-5 py-4 border-b border-gray-100 dark:border-gray-800 bg-gray-50/70 dark:bg-gray-850/50">
              <div className="flex items-center gap-2.5">
                <div className="w-8 h-8 rounded-lg bg-blue-100 dark:bg-blue-900/40 text-blue-600 dark:text-blue-400 flex items-center justify-center">
                  <RefreshCw className="w-4 h-4" />
                </div>
                <div>
                  <h3 className="text-sm font-bold text-gray-900 dark:text-white">
                    Rescan Project
                  </h3>
                  <p className="text-[11px] text-gray-500 dark:text-gray-400">
                    {rescanTargetJob.targetProject} {rescanTargetJob.appService ? `(${rescanTargetJob.appService})` : ''}
                  </p>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setRescanTargetJob(null)}
                className="p-1 rounded-lg text-gray-400 hover:text-gray-600 dark:hover:text-gray-200 hover:bg-gray-100 dark:hover:bg-gray-800"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="p-5 space-y-4">
              <p className="text-xs text-gray-600 dark:text-gray-300">
                Choose whether to re-scan the previously uploaded source or provide a new manifest/archive file:
              </p>

              <div className="space-y-3">
                {/* Option A: Re-scan previous source */}
                <label
                  onClick={() => setRescanSourceChoice('previous')}
                  className={`flex items-start gap-3 p-3.5 rounded-lg border cursor-pointer transition-all ${rescanSourceChoice === 'previous'
                    ? 'border-blue-500 bg-blue-50/50 dark:bg-blue-950/20 shadow-2xs'
                    : 'border-gray-200 dark:border-gray-750 hover:border-gray-300 bg-white dark:bg-gray-850'
                    }`}
                >
                  <input
                    type="radio"
                    name="rescan_choice"
                    checked={rescanSourceChoice === 'previous'}
                    onChange={() => setRescanSourceChoice('previous')}
                    className="mt-0.5 text-blue-600 focus:ring-blue-500"
                  />
                  <div className="flex-1 min-w-0">
                    <p className="text-xs font-semibold text-gray-900 dark:text-white">
                      Re-scan Previously Uploaded Source
                    </p>
                    <p className="text-[11px] text-gray-500 dark:text-gray-400 mt-0.5 truncate">
                      Source: {rescanTargetJob.source || 'Original scan source'}
                    </p>
                  </div>
                </label>

                {/* Option B: Upload new file */}
                <label
                  onClick={() => setRescanSourceChoice('new_file')}
                  className={`flex items-start gap-3 p-3.5 rounded-lg border cursor-pointer transition-all ${rescanSourceChoice === 'new_file'
                    ? 'border-blue-500 bg-blue-50/50 dark:bg-blue-950/20 shadow-2xs'
                    : 'border-gray-200 dark:border-gray-750 hover:border-gray-300 bg-white dark:bg-gray-850'
                    }`}
                >
                  <input
                    type="radio"
                    name="rescan_choice"
                    checked={rescanSourceChoice === 'new_file'}
                    onChange={() => setRescanSourceChoice('new_file')}
                    className="mt-0.5 text-blue-600 focus:ring-blue-500"
                  />
                  <div className="flex-1 min-w-0">
                    <p className="text-xs font-semibold text-gray-900 dark:text-white">
                      Upload a New File / Source
                    </p>
                    <p className="text-[11px] text-gray-500 dark:text-gray-400 mt-0.5">
                      Upload an updated manifest (pom.xml, package.json, requirements.txt) or archive (.zip, .spdx, .json)
                    </p>

                    {rescanSourceChoice === 'new_file' && (
                      <div className="mt-3 pt-3 border-t border-gray-100 dark:border-gray-800">
                        <input
                          ref={rescanFileInputRef}
                          type="file"
                          accept=".json,.xml,.spdx,.txt,.lock,.zip,.tar,.gz,pom.xml,package.json,requirements.txt"
                          onChange={(e) => {
                            const file = e.target.files?.[0];
                            if (file) {
                              setRescanNewFile(file);
                            }
                          }}
                          className="hidden"
                        />
                        <div className="flex items-center gap-2">
                          <button
                            type="button"
                            onClick={() => rescanFileInputRef.current?.click()}
                            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-xs font-medium text-gray-700 dark:text-gray-200 hover:bg-gray-50 dark:hover:bg-gray-750 cursor-pointer"
                          >
                            <Upload className="w-3.5 h-3.5" />
                            {rescanNewFile ? 'Change File' : 'Choose New File'}
                          </button>
                          {rescanNewFile ? (
                            <div className="flex items-center gap-1.5 text-xs text-emerald-600 dark:text-emerald-400 font-medium truncate">
                              <CheckCircle2 className="w-3.5 h-3.5 shrink-0" />
                              <span className="truncate">{rescanNewFile.name}</span>
                              <span className="text-[10px] text-gray-400">({(rescanNewFile.size / 1024).toFixed(1)} KB)</span>
                            </div>
                          ) : (
                            <span className="text-[11px] text-amber-600 dark:text-amber-400">
                              * Select a file to proceed
                            </span>
                          )}
                        </div>
                      </div>
                    )}
                  </div>
                </label>
              </div>
            </div>

            <div className="flex items-center justify-end gap-2 px-5 py-3 border-t border-gray-100 dark:border-gray-800 bg-gray-50/70 dark:bg-gray-850/50">
              <button
                type="button"
                onClick={() => setRescanTargetJob(null)}
                className="px-3.5 py-1.5 rounded-lg border border-gray-200 dark:border-gray-700 text-xs font-semibold text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-800 cursor-pointer"
              >
                Cancel
              </button>
              <button
                type="button"
                disabled={rescanningId === rescanTargetJob.id || (rescanSourceChoice === 'new_file' && !rescanNewFile)}
                onClick={executeRescan}
                className="inline-flex items-center gap-1.5 px-4 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white text-xs font-semibold cursor-pointer shadow-sm shadow-blue-500/20"
              >
                {rescanningId === rescanTargetJob.id ? (
                  <>
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    Starting Rescan...
                  </>
                ) : (
                  <>
                    <RefreshCw className="w-3.5 h-3.5" />
                    Start Rescan
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* PRE-SCAN DUPLICATE DETECTED WARNING MODAL */}
      {duplicateWarning?.isOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4">
          <div className="bg-white dark:bg-[#111C2E] border border-gray-200 dark:border-gray-800 rounded-2xl max-w-md w-full p-6 shadow-2xl relative animate-in fade-in zoom-in-95 duration-150">

            {/* CROSS [X] BUTTON TO THROW BACKWARDS */}
            <button
              type="button"
              onClick={() => {
                setDuplicateWarning(null);
                const el = document.getElementById('release-version-input');
                if (el) el.focus();
              }}
              className="absolute top-4 right-4 text-gray-400 hover:text-gray-700 dark:hover:text-white p-1 rounded-lg cursor-pointer"
              title="Close and go back to form"
            >
              <X className="w-5 h-5" />
            </button>

            <div className="flex items-center gap-3 text-amber-600 dark:text-amber-400 mb-3">
              <div className="p-2 rounded-xl bg-amber-50 dark:bg-amber-950/50 border border-amber-200 dark:border-amber-800">
                <AlertTriangle className="w-6 h-6 shrink-0" />
              </div>
              <div>
                <h3 className="text-base font-bold text-gray-900 dark:text-white">
                  {duplicateWarning.duplicateType === 'EXACT_FILE_EXISTS'
                    ? 'Duplicate File Detected'
                    : 'Duplicate Scan Detected'}
                </h3>
                <p className="text-[11px] text-gray-500 dark:text-gray-400">
                  {duplicateWarning.duplicateType === 'EXACT_FILE_EXISTS'
                    ? 'Identical file content was already scanned'
                    : 'Identical scan record already exists in database'}
                </p>
              </div>
            </div>

            <p className="text-xs text-gray-600 dark:text-gray-300 mb-4">
              {duplicateWarning.duplicateType === 'EXACT_FILE_EXISTS'
                ? 'This exact file has already been uploaded and analyzed. Duplicate files cannot be rescanned without modifications:'
                : 'This exact application version and content has already been scanned. Duplicate scans cannot be submitted as-is:'}
            </p>

            {/* MATCHED VALUES SUMMARY */}
            <div className="bg-gray-50 dark:bg-gray-900/60 rounded-xl p-3.5 space-y-2 text-xs border border-gray-100 dark:border-gray-800 font-mono mb-4">
              {duplicateWarning.fileName && (
                <div className="flex justify-between items-center">
                  <span className="text-gray-400 text-[11px]">Uploaded File:</span>
                  <span className="font-semibold text-blue-600 dark:text-blue-400 truncate max-w-[200px]">{duplicateWarning.fileName}</span>
                </div>
              )}
              <div className="flex justify-between items-center">
                <span className="text-gray-400 text-[11px]">Application:</span>
                <span className="font-semibold text-gray-900 dark:text-white">{duplicateWarning.appName}</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-gray-400 text-[11px]">Module / Service:</span>
                <span className="font-semibold text-gray-900 dark:text-white">{duplicateWarning.moduleName}</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-gray-400 text-[11px]">Version:</span>
                <span className="font-semibold text-amber-600 dark:text-amber-400">{duplicateWarning.version}</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-gray-400 text-[11px]">Completed At:</span>
                <span className="text-gray-500 text-[11px]">{duplicateWarning.scannedAt}</span>
              </div>
            </div>

            <p className="text-[11px] text-gray-500 dark:text-gray-400 mb-5">
              To proceed, please change the <strong>Release / Version</strong> (e.g. bump to a new version) or select an updated file.
            </p>

            {/* SINGLE GO BACK BUTTON */}
            <div className="flex justify-end">
              <button
                type="button"
                onClick={() => {
                  setDuplicateWarning(null);
                  const el = document.getElementById('release-version-input');
                  if (el) el.focus();
                }}
                className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-semibold bg-gray-900 dark:bg-white text-white dark:text-gray-900 rounded-lg hover:opacity-90 cursor-pointer transition-opacity"
              >
                <ArrowLeft className="w-3.5 h-3.5" />
                <span>Back to Form</span>
              </button>
            </div>

          </div>
        </div>
      )}
    </div>
  );
};

export default SecurityScans;
