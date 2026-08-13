import { useState, useEffect, useRef } from 'react';
import Head from 'next/head';
import {
  ShieldCheck,
  FileText,
  UploadCloud,
  Download,
  Search,
  BarChart3,
  CheckCircle2,
  AlertCircle,
  RefreshCw,
  Eye,
  User,
  Mail,
  Phone,
  Building,
  MapPin,
  FileBadge,
  Calendar,
  Lock,
  Zap,
} from 'lucide-react';

export default function Home() {
  const [apiUrl, setApiUrl] = useState(
    process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:8000'
  );
  const [activeTab, setActiveTab] = useState('redact'); // 'redact' | 'evaluate'
  const [backendStatus, setBackendStatus] = useState('connecting'); // 'connecting' | 'ready' | 'offline'

  // Ref for native file input picker
  const fileInputRef = useRef(null);

  // Redaction Tab State
  const [file, setFile] = useState(null);
  const [isDragOver, setIsDragOver] = useState(false);
  const [isRedacting, setIsRedacting] = useState(false);
  const [redactionProgressText, setRedactionProgressText] = useState(
    'Analyzing & Redacting PII...'
  );
  const [redactionResult, setRedactionResult] = useState(null);
  const [redactError, setRedactError] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedCategory, setSelectedCategory] = useState('ALL');

  // Evaluation Tab State
  const [isEvaluating, setIsEvaluating] = useState(false);
  const [evalResult, setEvalResult] = useState(null);
  const [evalError, setEvalError] = useState(null);

  // Auto Health-Check & Render Cold Start Warmup Hook
  useEffect(() => {
    let isMounted = true;
    const checkHealth = async () => {
      setBackendStatus('connecting');
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 15000);

        const response = await fetch(`${apiUrl.replace(/\/$/, '')}/health`, {
          signal: controller.signal,
        });
        clearTimeout(timeoutId);

        if (response.ok && isMounted) {
          setBackendStatus('ready');
          return;
        }
      } catch (err) {
        // Retry once after short delay for Render cold-starts
        try {
          const retryRes = await fetch(`${apiUrl.replace(/\/$/, '')}/health`);
          if (retryRes.ok && isMounted) {
            setBackendStatus('ready');
            return;
          }
        } catch (retryErr) {
          // Ignore retry error
        }
      }
      if (isMounted) {
        setBackendStatus('offline');
      }
    };

    checkHealth();
    return () => {
      isMounted = false;
    };
  }, [apiUrl]);

  const handleDropzoneClick = () => {
    if (fileInputRef.current) {
      fileInputRef.current.click();
    }
  };

  const handleFileChange = (e) => {
    const selected = e.target.files[0];
    if (selected && selected.name.toLowerCase().endsWith('.docx')) {
      setFile(selected);
      setRedactError(null);
    } else if (selected) {
      setRedactError('Please select a valid Microsoft Word (.docx) file.');
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setIsDragOver(false);
    const droppedFile = e.dataTransfer.files[0];
    if (droppedFile && droppedFile.name.toLowerCase().endsWith('.docx')) {
      setFile(droppedFile);
      setRedactError(null);
    } else {
      setRedactError('Please drop a valid Microsoft Word (.docx) file.');
    }
  };

  const handleRedact = async () => {
    if (!file) {
      setRedactError('Please select a .docx document to redact.');
      return;
    }

    setIsRedacting(true);
    setRedactError(null);
    setRedactionResult(null);
    setRedactionProgressText('Analyzing & Redacting PII...');
    const startTime = performance.now();

    // Cold-start detection timer: update message after 5 seconds
    const warmupTimer = setTimeout(() => {
      setRedactionProgressText(
        'Analyzing large prospectus document (processing thousands of paragraphs & tables)...'
      );
    }, 5000);

    // Extended 180-second (3 minute) AbortController timeout for large prospectus files
    const controller = new AbortController();
    const abortTimeout = setTimeout(() => {
      controller.abort();
    }, 180000);

    try {
      const formData = new FormData();
      formData.append('file', file);

      const response = await fetch(
        `${apiUrl.replace(/\/$/, '')}/redact?return_metadata=true`,
        {
          method: 'POST',
          body: formData,
          signal: controller.signal,
        }
      );

      if (!response.ok) {
        let errMessage = 'Redaction processing failed';
        if (response.status === 502 || response.status === 504) {
          errMessage =
            'Backend response delayed. Render free tier may still be warming up (~30-50s). Please try clicking Redact again.';
        } else {
          try {
            const errData = await response.json();
            errMessage = errData.detail || errMessage;
          } catch (_) {
            errMessage = `Server returned status ${response.status}`;
          }
        }
        throw new Error(errMessage);
      }

      const data = await response.json();
      const endTime = performance.now();
      const processingTime = ((endTime - startTime) / 1000).toFixed(2);

      setRedactionResult({
        ...data,
        processingTime,
      });
      setBackendStatus('ready');
    } catch (err) {
      if (err.name === 'AbortError') {
        setRedactError(
          'Processing large document timed out after 3 minutes. Please check server logs.'
        );
      } else {
        setRedactError(err.message || 'Failed to connect to the backend engine.');
      }
    } finally {
      clearTimeout(warmupTimer);
      clearTimeout(abortTimeout);
      setIsRedacting(false);
      setRedactionProgressText('Analyzing & Redacting PII...');
    }
  };

  const handleDownload = () => {
    if (!redactionResult || !redactionResult.redacted_file_base64) return;
    const byteCharacters = atob(redactionResult.redacted_file_base64);
    const byteNumbers = new Array(byteCharacters.length);
    for (let i = 0; i < byteCharacters.length; i++) {
      byteNumbers[i] = byteCharacters.charCodeAt(i);
    }
    const byteArray = new Uint8Array(byteNumbers);
    const blob = new Blob([byteArray], {
      type: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    });

    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = redactionResult.redacted_filename || 'redacted_document.docx';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const handleRunEvaluation = async () => {
    setIsEvaluating(true);
    setEvalError(null);

    const controller = new AbortController();
    const abortTimeout = setTimeout(() => controller.abort(), 60000);

    try {
      const response = await fetch(`${apiUrl.replace(/\/$/, '')}/evaluate`, {
        signal: controller.signal,
      });
      if (!response.ok) {
        const errData = await response.json();
        throw new Error(errData.detail || 'Evaluation request failed');
      }
      const data = await response.json();
      setEvalResult(data);
      setBackendStatus('ready');
    } catch (err) {
      if (err.name === 'AbortError') {
        setEvalError(
          'Evaluation request timed out. Render free tier may still be warming up. Please try again.'
        );
      } else {
        setEvalError(err.message || 'Failed to execute benchmark evaluation.');
      }
    } finally {
      clearTimeout(abortTimeout);
      setIsEvaluating(false);
    }
  };

  const getCategoryIcon = (type) => {
    switch (type) {
      case 'FULL_NAMES':
      case 'PERSON':
        return <User className="w-4 h-4 text-blue-400" />;
      case 'EMAIL':
      case 'EMAIL_ADDRESS':
        return <Mail className="w-4 h-4 text-indigo-400" />;
      case 'PHONE':
      case 'PHONE_NUMBER':
        return <Phone className="w-4 h-4 text-emerald-400" />;
      case 'COMPANY_NAMES':
      case 'ORGANIZATION':
        return <Building className="w-4 h-4 text-purple-400" />;
      case 'ADDRESSES':
      case 'LOCATION':
        return <MapPin className="w-4 h-4 text-amber-400" />;
      case 'SSN_GOVT_ID':
      case 'GOVT_ID':
        return <FileBadge className="w-4 h-4 text-rose-400" />;
      case 'DATE_OF_BIRTH':
      case 'DATE_TIME':
        return <Calendar className="w-4 h-4 text-teal-400" />;
      default:
        return <ShieldCheck className="w-4 h-4 text-gray-400" />;
    }
  };

  const renderStatusBadge = () => {
    if (backendStatus === 'ready') {
      return (
        <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs font-medium whitespace-nowrap">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
          Backend Ready
        </div>
      );
    } else if (backendStatus === 'connecting') {
      return (
        <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-amber-500/10 border border-amber-500/30 text-amber-300 text-xs font-medium whitespace-nowrap">
          <span className="w-2 h-2 rounded-full bg-amber-400 animate-ping" />
          Connecting / Waking server...
        </div>
      );
    } else {
      return (
        <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs font-medium whitespace-nowrap">
          <span className="w-2 h-2 rounded-full bg-rose-400" />
          Server Offline
        </div>
      );
    }
  };

  const detectedList = redactionResult?.metadata?.detected_entities || [];
  const filteredEntities = detectedList.filter((ent) => {
    const matchesSearch =
      ent.original_text.toLowerCase().includes(searchTerm.toLowerCase()) ||
      ent.pseudonym.toLowerCase().includes(searchTerm.toLowerCase()) ||
      ent.entity_type.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesCategory =
      selectedCategory === 'ALL' || ent.entity_type === selectedCategory;
    return matchesSearch && matchesCategory;
  });

  return (
    <div className="min-h-screen pb-16">
      <Head>
        <title>Enterprise PII Redaction Engine</title>
        <meta
          name="description"
          content="Production-Ready PII Redaction Tool with Presidio, spaCy NER, and Faker Pseudonymization"
        />
        <link rel="icon" href="/favicon.ico" />
      </Head>

      {/* Navigation / Header */}
      <header className="glass-panel sticky top-0 z-50 border-b border-slate-800/80 px-6 py-4">
        <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-blue-600/20 border border-blue-500/30 text-blue-400">
              <ShieldCheck className="w-7 h-7" />
            </div>
            <div>
              <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
                Enterprise PII Redaction Engine
                <span className="text-xs px-2 py-0.5 rounded-full bg-blue-500/20 text-blue-300 border border-blue-500/30">
                  FastAPI + Presidio
                </span>
              </h1>
              <p className="text-xs text-slate-400">
                Hybrid spaCy NER & Deterministic Pattern Pseudonymization
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-3 w-full md:w-auto justify-end">
            {/* Live Backend Status Badge */}
            {renderStatusBadge()}

            {/* Expanded Full-Width API URL Config Box */}
            <div className="flex items-center gap-2 bg-slate-900/80 border border-slate-800 rounded-lg px-3 py-1.5 text-xs w-full max-w-lg">
              <Lock className="w-3.5 h-3.5 text-slate-400 flex-shrink-0" />
              <span className="text-slate-400 font-medium flex-shrink-0">API Endpoint:</span>
              <input
                type="text"
                value={apiUrl}
                onChange={(e) => setApiUrl(e.target.value)}
                placeholder="http://127.0.0.1:7860"
                className="bg-transparent text-slate-200 focus:outline-none w-full font-mono text-[11px] truncate"
              />
            </div>
          </div>
        </div>
      </header>

      {/* Main Container */}
      <main className="max-w-7xl mx-auto px-6 pt-8">
        {/* Navigation Tabs */}
        <div className="flex space-x-2 border-b border-slate-800 mb-8">
          <button
            onClick={() => setActiveTab('redact')}
            className={`flex items-center gap-2 px-5 py-3 font-medium text-sm rounded-t-xl transition-all ${
              activeTab === 'redact'
                ? 'bg-blue-600/20 text-blue-400 border-b-2 border-blue-500'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/40'
            }`}
          >
            <FileText className="w-4 h-4" />
            Document Redactor
          </button>
          <button
            onClick={() => setActiveTab('evaluate')}
            className={`flex items-center gap-2 px-5 py-3 font-medium text-sm rounded-t-xl transition-all ${
              activeTab === 'evaluate'
                ? 'bg-blue-600/20 text-blue-400 border-b-2 border-blue-500'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/40'
            }`}
          >
            <BarChart3 className="w-4 h-4" />
            Evaluation Dashboard
          </button>
        </div>

        {/* TAB 1: DOCUMENT REDACTOR */}
        {activeTab === 'redact' && (
          <div className="space-y-8">
            {/* Upload Zone */}
            <div className="glass-panel rounded-2xl p-8">
              <div
                onClick={handleDropzoneClick}
                onDragOver={(e) => {
                  e.preventDefault();
                  setIsDragOver(true);
                }}
                onDragLeave={() => setIsDragOver(false)}
                onDrop={handleDrop}
                className={`dropzone rounded-xl p-10 text-center cursor-pointer flex flex-col items-center justify-center ${
                  isDragOver ? 'active' : ''
                }`}
              >
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".docx"
                  onChange={handleFileChange}
                  className="hidden"
                  id="docx-file-input"
                />
                <div className="flex flex-col items-center pointer-events-none">
                  <div className="p-4 rounded-full bg-blue-500/10 border border-blue-500/20 text-blue-400 mb-4">
                    <UploadCloud className="w-10 h-10" />
                  </div>
                  <h3 className="text-lg font-semibold text-white mb-1">
                    {file ? file.name : 'Upload .docx Document'}
                  </h3>
                  <p className="text-sm text-slate-400 max-w-md">
                    Drag and drop your Microsoft Word prospectus document here, or{' '}
                    <span className="text-blue-400 underline font-medium">browse file</span>
                  </p>
                  <p className="text-xs text-slate-500 mt-2">
                    Supports Red Herring Prospectus.docx with layout & run formatting preservation
                  </p>
                </div>
              </div>

              {redactError && (
                <div className="mt-4 p-4 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-300 text-sm flex items-center gap-3">
                  <AlertCircle className="w-5 h-5 text-rose-400 flex-shrink-0" />
                  <span>{redactError}</span>
                </div>
              )}

              <div className="mt-6 flex justify-end">
                <button
                  onClick={handleRedact}
                  disabled={!file || isRedacting}
                  className={`glass-button px-6 py-3 rounded-xl font-semibold text-sm text-white flex items-center gap-2 ${
                    !file || isRedacting ? 'opacity-50 cursor-not-allowed' : ''
                  }`}
                >
                  {isRedacting ? (
                    <>
                      <RefreshCw className="w-4 h-4 animate-spin" />
                      <span>{redactionProgressText}</span>
                    </>
                  ) : (
                    <>
                      <Zap className="w-4 h-4" />
                      Redact Document
                    </>
                  )}
                </button>
              </div>
            </div>

            {/* Results Display Panel */}
            {redactionResult && (
              <div className="space-y-8 animate-fadeIn">
                {/* Action Banner */}
                <div className="glass-panel rounded-2xl p-6 flex flex-col sm:flex-row items-center justify-between gap-4 bg-gradient-to-r from-blue-900/30 to-indigo-900/30 border border-blue-500/20">
                  <div className="flex items-center gap-4">
                    <div className="p-3 rounded-xl bg-emerald-500/20 border border-emerald-500/30 text-emerald-400">
                      <CheckCircle2 className="w-6 h-6" />
                    </div>
                    <div>
                      <h4 className="text-base font-bold text-white">
                        Redaction Complete
                      </h4>
                      <p className="text-xs text-slate-300">
                        {redactionResult.metadata.total_entities_found} PII entities replaced with persistent pseudonyms in {redactionResult.processingTime} seconds.
                      </p>
                    </div>
                  </div>

                  <button
                    onClick={handleDownload}
                    className="glass-button px-5 py-2.5 rounded-xl font-semibold text-xs text-white flex items-center gap-2 whitespace-nowrap"
                  >
                    <Download className="w-4 h-4" />
                    Download Redacted .docx
                  </button>
                </div>

                {/* Summary Statistics Cards */}
                <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                  <div className="glass-panel rounded-xl p-5 border border-slate-800">
                    <p className="text-xs font-medium text-slate-400 mb-1">Total PII Entities</p>
                    <p className="text-2xl font-extrabold text-white">
                      {redactionResult.metadata.total_entities_found}
                    </p>
                  </div>
                  <div className="glass-panel rounded-xl p-5 border border-slate-800">
                    <p className="text-xs font-medium text-slate-400 mb-1">Unique Mappings</p>
                    <p className="text-2xl font-extrabold text-blue-400">
                      {Object.keys(redactionResult.metadata.pseudonym_mappings).length}
                    </p>
                  </div>
                  <div className="glass-panel rounded-xl p-5 border border-slate-800">
                    <p className="text-xs font-medium text-slate-400 mb-1">Entity Categories</p>
                    <p className="text-2xl font-extrabold text-indigo-400">
                      {Object.keys(redactionResult.metadata.entity_counts).length}
                    </p>
                  </div>
                  <div className="glass-panel rounded-xl p-5 border border-slate-800">
                    <p className="text-xs font-medium text-slate-400 mb-1">Processing Time</p>
                    <p className="text-2xl font-extrabold text-emerald-400">
                      {redactionResult.processingTime} s
                    </p>
                  </div>
                </div>

                {/* Breakdown Per PII Category */}
                <div className="glass-panel rounded-2xl p-6">
                  <h3 className="text-sm font-semibold text-slate-300 mb-4 uppercase tracking-wider">
                    PII Entity Breakdown
                  </h3>
                  <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-3">
                    {Object.entries(redactionResult.metadata.entity_counts).map(
                      ([etype, count]) => (
                        <div
                          key={etype}
                          onClick={() => setSelectedCategory(etype)}
                          className={`p-3 rounded-xl border cursor-pointer transition-all ${
                            selectedCategory === etype
                              ? 'bg-blue-600/30 border-blue-500/50'
                              : 'bg-slate-900/50 border-slate-800 hover:border-slate-700'
                          }`}
                        >
                          <div className="flex items-center gap-2 mb-1">
                            {getCategoryIcon(etype)}
                            <span className="text-[11px] font-semibold text-slate-300 truncate">
                              {etype}
                            </span>
                          </div>
                          <p className="text-lg font-bold text-white">{count}</p>
                        </div>
                      )
                    )}
                  </div>
                </div>

                {/* Searchable Pseudonym Mapping Table */}
                <div className="glass-panel rounded-2xl p-6">
                  <div className="flex flex-col sm:flex-row items-center justify-between gap-4 mb-6">
                    <div>
                      <h3 className="text-base font-bold text-white">
                        Pseudonym Substitution Table
                      </h3>
                      <p className="text-xs text-slate-400">
                        Persistent mapping dictionary preserving entity references
                      </p>
                    </div>

                    <div className="flex items-center gap-3 w-full sm:w-auto">
                      {/* Search Bar */}
                      <div className="relative w-full sm:w-64">
                        <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
                        <input
                          type="text"
                          placeholder="Search PII or fake text..."
                          value={searchTerm}
                          onChange={(e) => setSearchTerm(e.target.value)}
                          className="w-full bg-slate-900/80 border border-slate-800 rounded-xl pl-9 pr-3 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
                        />
                      </div>

                      {/* Category Filter */}
                      <select
                        value={selectedCategory}
                        onChange={(e) => setSelectedCategory(e.target.value)}
                        className="bg-slate-900/80 border border-slate-800 rounded-xl px-3 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-blue-500"
                      >
                        <option value="ALL">All Categories</option>
                        {Object.keys(redactionResult.metadata.entity_counts).map((c) => (
                          <option key={c} value={c}>
                            {c}
                          </option>
                        ))}
                      </select>
                    </div>
                  </div>

                  {/* Table */}
                  <div className="overflow-x-auto rounded-xl border border-slate-800">
                    <table className="w-full text-left border-collapse">
                      <thead>
                        <tr className="bg-slate-900/80 border-b border-slate-800 text-xs text-slate-400 font-medium">
                          <th className="p-3.5">Category</th>
                          <th className="p-3.5">Original Sensitive PII</th>
                          <th className="p-3.5">Substituted Pseudonym</th>
                          <th className="p-3.5 text-center">Confidence</th>
                          <th className="p-3.5 text-right">Occurrences</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/60 text-xs">
                        {filteredEntities.length > 0 ? (
                          filteredEntities.map((ent, idx) => (
                            <tr
                              key={idx}
                              className="hover:bg-slate-800/30 transition-colors"
                            >
                              <td className="p-3.5 flex items-center gap-2 font-medium">
                                {getCategoryIcon(ent.entity_type)}
                                <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono text-[11px]">
                                  {ent.entity_type}
                                </span>
                              </td>
                              <td className="p-3.5 text-rose-300 font-mono">
                                {ent.original_text}
                              </td>
                              <td className="p-3.5 text-emerald-300 font-mono">
                                {ent.pseudonym}
                              </td>
                              <td className="p-3.5 text-center font-mono text-slate-400">
                                {(ent.confidence_score * 100).toFixed(0)}%
                              </td>
                              <td className="p-3.5 text-right font-bold text-white">
                                {ent.count}
                              </td>
                            </tr>
                          ))
                        ) : (
                          <tr>
                            <td
                              colSpan={5}
                              className="p-8 text-center text-slate-500 italic"
                            >
                              No PII entities matching search criteria.
                            </td>
                          </tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* TAB 2: EVALUATION DASHBOARD */}
        {activeTab === 'evaluate' && (
          <div className="space-y-8">
            <div className="glass-panel rounded-2xl p-8 flex flex-col md:flex-row items-center justify-between gap-6">
              <div>
                <h2 className="text-xl font-bold text-white mb-1">
                  Red Herring Prospectus Ground Truth Evaluation
                </h2>
                <p className="text-xs text-slate-400 max-w-xl">
                  Run automated benchmark accuracy test evaluating Precision, Recall, and F1 Score against annotated ground truth data (`red_herring_ground_truth.json`).
                </p>
              </div>

              <button
                onClick={handleRunEvaluation}
                disabled={isEvaluating}
                className="glass-button px-6 py-3 rounded-xl font-semibold text-sm text-white flex items-center gap-2 whitespace-nowrap"
              >
                {isEvaluating ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin" />
                    Running Evaluation...
                  </>
                ) : (
                  <>
                    <BarChart3 className="w-4 h-4" />
                    Run Benchmark Evaluation
                  </>
                )}
              </button>
            </div>

            {evalError && (
              <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-300 text-sm flex items-center gap-3">
                <AlertCircle className="w-5 h-5 text-rose-400 flex-shrink-0" />
                <span>{evalError}</span>
              </div>
            )}

            {evalResult && (
              <div className="space-y-8 animate-fadeIn">
                {/* Metric Cards */}
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-6">
                  <div className="glass-panel rounded-2xl p-6 border-t-4 border-blue-500">
                    <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                      Precision
                    </p>
                    <p className="text-4xl font-extrabold text-white mb-2">
                      {(evalResult.overall.precision * 100).toFixed(1)}%
                    </p>
                    <p className="text-xs text-slate-400">
                      TP: {evalResult.overall.tp} | FP: {evalResult.overall.fp}
                    </p>
                  </div>

                  <div className="glass-panel rounded-2xl p-6 border-t-4 border-indigo-500">
                    <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                      Recall
                    </p>
                    <p className="text-4xl font-extrabold text-white mb-2">
                      {(evalResult.overall.recall * 100).toFixed(1)}%
                    </p>
                    <p className="text-xs text-slate-400">
                      TP: {evalResult.overall.tp} | FN: {evalResult.overall.fn}
                    </p>
                  </div>

                  <div className="glass-panel rounded-2xl p-6 border-t-4 border-emerald-500">
                    <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                      F1 Score
                    </p>
                    <p className="text-4xl font-extrabold text-emerald-400 mb-2">
                      {(evalResult.overall.f1_score * 100).toFixed(1)}%
                    </p>
                    <p className="text-xs text-slate-400">
                      Harmonic Mean of Precision & Recall
                    </p>
                  </div>
                </div>

                {/* Category-Level Performance Breakdown Table */}
                <div className="glass-panel rounded-2xl p-6">
                  <h3 className="text-base font-bold text-white mb-4">
                    Category Performance Breakdown
                  </h3>
                  <div className="overflow-x-auto rounded-xl border border-slate-800">
                    <table className="w-full text-left border-collapse">
                      <thead>
                        <tr className="bg-slate-900/80 border-b border-slate-800 text-xs text-slate-400 font-medium">
                          <th className="p-3.5">PII Category</th>
                          <th className="p-3.5 text-center">True Positives (TP)</th>
                          <th className="p-3.5 text-center">False Positives (FP)</th>
                          <th className="p-3.5 text-center">False Negatives (FN)</th>
                          <th className="p-3.5 text-center">Precision</th>
                          <th className="p-3.5 text-center">Recall</th>
                          <th className="p-3.5 text-center">F1 Score</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/60 text-xs">
                        {Object.entries(evalResult.by_entity_type).map(
                          ([category, metrics]) => (
                            <tr
                              key={category}
                              className="hover:bg-slate-800/30 transition-colors"
                            >
                              <td className="p-3.5 flex items-center gap-2 font-medium">
                                {getCategoryIcon(category)}
                                <span className="font-mono text-slate-200">
                                  {category}
                                </span>
                              </td>
                              <td className="p-3.5 text-center font-bold text-emerald-400">
                                {metrics.tp}
                              </td>
                              <td className="p-3.5 text-center font-bold text-amber-400">
                                {metrics.fp}
                              </td>
                              <td className="p-3.5 text-center font-bold text-rose-400">
                                {metrics.fn}
                              </td>
                              <td className="p-3.5 text-center font-mono">
                                {(metrics.precision * 100).toFixed(1)}%
                              </td>
                              <td className="p-3.5 text-center font-mono">
                                {(metrics.recall * 100).toFixed(1)}%
                              </td>
                              <td className="p-3.5 text-center font-bold font-mono text-blue-400">
                                {(metrics.f1_score * 100).toFixed(1)}%
                              </td>
                            </tr>
                          )
                        )}
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}
      </main>
    </div>
  );
}
