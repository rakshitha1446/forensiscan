/**
 * PixelTruth v3.0 – Frontend Client
 * detector.js  |  Multi-modal AI forensic detection
 *
 * Handles UI interactions for Image, Video, Audio, and Text analysis.
 * Communicates with the Node.js backend API.
 */

'use strict';

/* =========================================
   CONFIG
   ========================================= */
const API_BASE = window.location.origin;
const API_ANALYZE_FILE = `${API_BASE}/api/analyze`;
const API_ANALYZE_TEXT = `${API_BASE}/api/analyze-text`;

const MEDIA_CONFIG = {
  image: {
    accept: '.jpg,.jpeg,.png,.webp,.bmp',
    types: ['image/jpeg', 'image/png', 'image/webp', 'image/bmp'],
    title: 'Drop your image here',
    formats: ['JPG', 'PNG', 'WEBP', 'BMP'],
    icon: '🖼️',
    label: 'Image Analysis',
    steps: [
      { id: 'init',     label: 'Initializing forensic engine',      pct: 8  },
      { id: 'meta',     label: 'Analyzing metadata & EXIF data',    pct: 18 },
      { id: 'pixel',    label: 'Computing pixel distribution',      pct: 32 },
      { id: 'noise',    label: 'Scanning noise patterns',           pct: 46 },
      { id: 'freq',     label: 'Running frequency domain analysis', pct: 60 },
      { id: 'edge',     label: 'Detecting edge coherence patterns', pct: 72 },
      { id: 'artifact', label: 'Checking AI model artifacts',       pct: 84 },
      { id: 'model',    label: 'Classifying with forensic model',   pct: 94 },
      { id: 'report',   label: 'Generating forensic report',        pct: 100 },
    ],
    metricOrder: [
      { key: 'noiseConsistency',   label: 'Noise Patterns'       },
      { key: 'edgeArtifacts',      label: 'Edge Artifacts'       },
      { key: 'pixelEntropy',       label: 'Pixel Entropy'        },
      { key: 'freqAnomaly',        label: 'Frequency Anomaly'    },
      { key: 'compressionAnomaly', label: 'Compression Anomaly'  },
      { key: 'textureRepetition',  label: 'Texture Repetition'   },
      { key: 'colorDistribution',  label: 'Color Distribution'   },
      { key: 'metadataIntegrity',  label: 'Metadata Flags'       },
    ],
  },
  video: {
    accept: '.mp4,.webm,.mov,.avi',
    types: ['video/mp4', 'video/webm', 'video/quicktime', 'video/x-msvideo'],
    title: 'Drop your video here',
    formats: ['MP4', 'WEBM', 'MOV', 'AVI'],
    icon: '🎬',
    label: 'Video Analysis',
    steps: [
      { id: 'init',    label: 'Initializing video engine',          pct: 10 },
      { id: 'meta',    label: 'Reading container metadata',         pct: 22 },
      { id: 'format',  label: 'Analyzing container format',         pct: 36 },
      { id: 'comp',    label: 'Scanning compression patterns',      pct: 50 },
      { id: 'temporal',label: 'Evaluating temporal coherence',      pct: 65 },
      { id: 'bytes',   label: 'Analyzing byte distributions',       pct: 78 },
      { id: 'struct',  label: 'Checking structural integrity',      pct: 90 },
      { id: 'report',  label: 'Generating forensic report',         pct: 100 },
    ],
    metricOrder: [
      { key: 'metadataIntegrity',   label: 'Metadata Integrity'    },
      { key: 'containerAnalysis',   label: 'Container Format'      },
      { key: 'compressionPattern',  label: 'Compression Pattern'   },
      { key: 'temporalCoherence',   label: 'Temporal Coherence'    },
      { key: 'byteDistribution',    label: 'Byte Distribution'     },
      { key: 'structuralAnomaly',   label: 'Structural Anomaly'    },
    ],
  },
  audio: {
    accept: '.mp3,.wav,.ogg,.flac',
    types: ['audio/mpeg', 'audio/wav', 'audio/ogg', 'audio/flac', 'audio/x-wav', 'audio/mp3', 'audio/wave'],
    title: 'Drop your audio here',
    formats: ['MP3', 'WAV', 'OGG', 'FLAC'],
    icon: '🎵',
    label: 'Audio Analysis',
    steps: [
      { id: 'init',     label: 'Initializing audio engine',         pct: 10 },
      { id: 'meta',     label: 'Reading audio metadata',            pct: 20 },
      { id: 'spectral', label: 'Analyzing spectral patterns',       pct: 36 },
      { id: 'noise',    label: 'Profiling noise floor',             pct: 50 },
      { id: 'amp',      label: 'Computing amplitude distribution',  pct: 65 },
      { id: 'freq',     label: 'Evaluating frequency uniformity',   pct: 78 },
      { id: 'struct',   label: 'Checking structural regularity',    pct: 90 },
      { id: 'report',   label: 'Generating forensic report',        pct: 100 },
    ],
    metricOrder: [
      { key: 'metadataIntegrity',     label: 'Metadata Integrity'     },
      { key: 'spectralPattern',       label: 'Spectral Pattern'       },
      { key: 'noiseFloor',            label: 'Noise Floor'            },
      { key: 'amplitudeDistribution', label: 'Amplitude Distribution' },
      { key: 'frequencyUniformity',   label: 'Frequency Uniformity'   },
      { key: 'structuralRegularity',  label: 'Structural Regularity'  },
    ],
  },
  text: {
    icon: '📝',
    label: 'Text Analysis',
    steps: [
      { id: 'init',     label: 'Initializing text engine',          pct: 10 },
      { id: 'burst',    label: 'Measuring sentence burstiness',     pct: 24 },
      { id: 'vocab',    label: 'Analyzing vocabulary diversity',     pct: 38 },
      { id: 'perplex',  label: 'Computing perplexity proxy',        pct: 52 },
      { id: 'repeat',   label: 'Detecting repetition patterns',     pct: 66 },
      { id: 'struct',   label: 'Evaluating structural uniformity',  pct: 78 },
      { id: 'ling',     label: 'Scanning linguistic markers',       pct: 90 },
      { id: 'report',   label: 'Generating forensic report',        pct: 100 },
    ],
    metricOrder: [
      { key: 'burstiness',            label: 'Burstiness'              },
      { key: 'vocabularyDiversity',   label: 'Vocabulary Diversity'    },
      { key: 'perplexityProxy',       label: 'Perplexity Proxy'        },
      { key: 'repetitionPatterns',    label: 'Repetition Patterns'     },
      { key: 'structuralUniformity',  label: 'Structural Uniformity'   },
      { key: 'linguisticMarkers',     label: 'Linguistic Markers'      },
    ],
  },
};

/* =========================================
   DOM REFERENCES
   ========================================= */
const $ = (id) => document.getElementById(id);

const mediaTabs      = $('mediaTabs');
const tabIndicator   = $('tabIndicator');
const uploadCard     = $('uploadCard');
const uploadZone     = $('uploadZone');
const fileInput      = $('fileInput');
const browseBtn      = $('browseBtn');
const uploadTitle    = $('uploadTitle');
const uploadFormats  = $('uploadFormats');
const uploadLimit    = $('uploadLimit');
const textInputCard  = $('textInputCard');
const textArea       = $('textArea');
const charCount      = $('charCount');
const analyzeTextBtn = $('analyzeTextBtn');
const clearTextBtn   = $('clearTextBtn');
const analysisPanel  = $('analysisPanel');
const previewCard    = $('previewCard');
const previewLabel   = $('previewLabel');
const previewImage   = $('previewImage');
const previewVideo   = $('previewVideo');
const previewAudio   = $('previewAudio');
const audioPlayer    = $('audioPlayer');
const previewText    = $('previewText');
const scanOverlay    = $('scanOverlay');
const mediaMeta      = $('mediaMeta');
const processingCard = $('processingCard');
const processingTitle= $('processingTitle');
const processingStep = $('processingStep');
const processingStages=$('processingStages');
const progressFill   = $('progressFill');
const progressPct    = $('progressPct');
const resultsCard    = $('resultsCard');
const verdictBadge   = $('verdictBadge');
const verdictIcon    = $('verdictIcon');
const verdictTitle   = $('verdictTitle');
const confidenceArc  = $('confidenceArc');
const confidenceValue= $('confidenceValue');
const contentTypeBadge=$('contentTypeBadge');
const ctbIcon        = $('ctbIcon');
const ctbText        = $('ctbText');
const forensicMetrics= $('forensicMetrics');
const explanationText= $('explanationText');
const resetBtn       = $('resetBtn');
const analyzeAnotherBtn=$('analyzeAnotherBtn');
const downloadReportBtn=$('downloadReportBtn');

let currentMediaType = 'image';
let currentAnalysis  = null;
let currentFile      = null;

/* =========================================
   API HEALTH CHECK ON LOAD
   ========================================= */
window.addEventListener('DOMContentLoaded', async () => {
  updateTabIndicator();

  try {
    const res  = await fetch(`${API_BASE}/api/health`);
    const data = await res.json();
    if (data.status === 'ok') {
      console.log(`[PixelTruth] Backend connected: ${data.engine} v${data.version}`);
      console.log(`[PixelTruth] Capabilities: ${data.capabilities.join(', ')}`);
    }
  } catch {
    console.warn('[PixelTruth] Backend not reachable – check that server.js is running.');
    showBanner('⚠️ Cannot connect to the backend server. Please run: npm start', 'warn');
  }
});

function showBanner(msg, type = 'warn') {
  const banner = document.createElement('div');
  banner.style.cssText = `
    position:fixed; top:70px; left:50%; transform:translateX(-50%);
    background:${type === 'warn' ? 'rgba(255,140,42,0.15)' : 'rgba(0,229,160,0.15)'};
    border:1px solid ${type === 'warn' ? 'rgba(255,140,42,0.5)' : 'rgba(0,229,160,0.5)'};
    color:${type === 'warn' ? '#ff8c2a' : '#00e5a0'};
    padding:12px 24px; border-radius:12px; font-size:14px; font-weight:600;
    z-index:9999; backdrop-filter:blur(10px); max-width:520px; text-align:center;
    box-shadow:0 4px 24px rgba(0,0,0,0.4);
  `;
  banner.textContent = msg;
  document.body.appendChild(banner);
  setTimeout(() => banner.remove(), 7000);
}

/* =========================================
   MEDIA TYPE TAB SWITCHING
   ========================================= */
document.querySelectorAll('.media-tab').forEach(tab => {
  tab.addEventListener('click', () => {
    const type = tab.dataset.type;
    switchMediaType(type);
  });
});

function switchMediaType(type) {
  currentMediaType = type;

  // Update tab active states
  document.querySelectorAll('.media-tab').forEach(t => {
    t.classList.toggle('active', t.dataset.type === type);
    t.setAttribute('aria-selected', t.dataset.type === type ? 'true' : 'false');
  });
  updateTabIndicator();

  // Show/hide correct input
  if (type === 'text') {
    uploadCard.style.display = 'none';
    textInputCard.style.display = '';
  } else {
    uploadCard.style.display = '';
    textInputCard.style.display = 'none';
    const config = MEDIA_CONFIG[type];
    fileInput.accept = config.accept;
    uploadTitle.textContent = config.title;
    uploadFormats.innerHTML = config.formats.map(f => `<span class="format-tag">${f}</span>`).join('');
  }

  // Reset analysis panel if visible
  resetUI();
}

function updateTabIndicator() {
  const activeTab = document.querySelector('.media-tab.active');
  if (activeTab && tabIndicator) {
    const tabRect = activeTab.getBoundingClientRect();
    const containerRect = mediaTabs.getBoundingClientRect();

    tabIndicator.style.width = tabRect.width + 'px';
    tabIndicator.style.left = (tabRect.left - containerRect.left) + 'px';
  }
}

window.addEventListener('resize', updateTabIndicator);

/* =========================================
   FILE UPLOAD HANDLERS
   ========================================= */
browseBtn.addEventListener('click', (e) => { e.stopPropagation(); fileInput.click(); });

uploadZone.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); fileInput.click(); }
});

fileInput.addEventListener('change', (e) => {
  const file = e.target.files[0];
  if (file) handleFile(file);
});

uploadZone.addEventListener('dragover',  (e) => { e.preventDefault(); uploadZone.classList.add('drag-over'); });
uploadZone.addEventListener('dragleave', ()  => uploadZone.classList.remove('drag-over'));
uploadZone.addEventListener('drop', (e) => {
  e.preventDefault();
  uploadZone.classList.remove('drag-over');
  const file = e.dataTransfer.files[0];
  if (file && isValidType(file)) handleFile(file);
  else showBanner(`Please upload a valid ${currentMediaType} file.`, 'warn');
});

resetBtn.addEventListener('click', resetUI);
analyzeAnotherBtn.addEventListener('click', resetUI);

function isValidType(file) {
  const config = MEDIA_CONFIG[currentMediaType];
  if (!config || !config.types) return false;
  return config.types.includes(file.type);
}

/* =========================================
   TEXT ANALYSIS HANDLERS
   ========================================= */
textArea.addEventListener('input', () => {
  const len = textArea.value.length;
  charCount.textContent = `${len.toLocaleString()} characters`;
  analyzeTextBtn.disabled = len < 20;
});

clearTextBtn.addEventListener('click', () => {
  textArea.value = '';
  charCount.textContent = '0 characters';
  analyzeTextBtn.disabled = true;
});

analyzeTextBtn.addEventListener('click', () => {
  const text = textArea.value.trim();
  if (text.length >= 20) {
    handleTextAnalysis(text);
  }
});

/* =========================================
   FILE HANDLING → PREVIEW → API CALL
   ========================================= */
function handleFile(file) {
  if (!isValidType(file)) {
    showBanner(`Unsupported file type. Please upload a valid ${currentMediaType} file.`, 'warn');
    return;
  }
  if (file.size > 50 * 1024 * 1024) {
    showBanner('File too large. Maximum size is 50MB.', 'warn');
    return;
  }

  currentFile = file;

  // Show preview based on type
  hideAllPreviews();

  if (currentMediaType === 'image') {
    const reader = new FileReader();
    reader.onload = (ev) => {
      previewImage.src = ev.target.result;
      previewImage.style.display = 'block';
      previewImage.onload = () => showAnalysisPanel(file);
    };
    reader.readAsDataURL(file);
  } else if (currentMediaType === 'video') {
    const url = URL.createObjectURL(file);
    previewVideo.src = url;
    previewVideo.style.display = 'block';
    showAnalysisPanel(file);
  } else if (currentMediaType === 'audio') {
    const url = URL.createObjectURL(file);
    audioPlayer.src = url;
    previewAudio.style.display = 'flex';
    showAnalysisPanel(file);
  }
}

function handleTextAnalysis(text) {
  currentFile = null;
  hideAllPreviews();

  previewText.textContent = text.length > 500 ? text.substring(0, 500) + '…' : text;
  previewText.style.display = 'block';
  previewLabel.textContent = 'Text Content';

  mediaMeta.innerHTML = `
    <div class="meta-item">Characters: <span>${text.length.toLocaleString()}</span></div>
    <div class="meta-item">Words: <span>${text.split(/\s+/).filter(w => w.length > 0).length}</span></div>
    <div class="meta-item">Status: <span style="color:var(--cyan)">Analyzing…</span></div>
  `;

  textInputCard.style.display = 'none';
  mediaTabs.style.display = 'none';
  analysisPanel.classList.add('show');
  processingCard.style.display = 'block';
  resultsCard.style.display = 'none';

  const config = MEDIA_CONFIG.text;
  processingTitle.textContent = 'Analyzing Text';
  buildStageList(config.steps);

  runTextAnalysis(text, config.steps);
}

function hideAllPreviews() {
  previewImage.style.display = 'none';
  previewVideo.style.display = 'none';
  previewAudio.style.display = 'none';
  previewText.style.display = 'none';
}

function showAnalysisPanel(file) {
  const config = MEDIA_CONFIG[currentMediaType];
  previewLabel.textContent = `Uploaded ${currentMediaType.charAt(0).toUpperCase() + currentMediaType.slice(1)}`;

  mediaMeta.innerHTML = `
    <div class="meta-item">File: <span>${file.name}</span></div>
    <div class="meta-item">Size: <span>${formatBytes(file.size)}</span></div>
    <div class="meta-item">Type: <span>${file.type.split('/')[1].toUpperCase()}</span></div>
    <div class="meta-item">Status: <span style="color:var(--cyan)">Uploading…</span></div>
  `;

  uploadCard.style.display = 'none';
  mediaTabs.style.display = 'none';
  analysisPanel.classList.add('show');
  processingCard.style.display = 'block';
  resultsCard.style.display = 'none';

  processingTitle.textContent = `Analyzing ${currentMediaType.charAt(0).toUpperCase() + currentMediaType.slice(1)}`;
  buildStageList(config.steps);
  analysisPanel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

  runFileAnalysis(file, config);
}

function buildStageList(steps) {
  processingStages.innerHTML = '';
  steps.forEach(step => {
    const el = document.createElement('div');
    el.className = 'stage-item';
    el.id = 'stage-' + step.id;
    el.innerHTML = `<div class="stage-dot"></div><span>${step.label}</span>`;
    processingStages.appendChild(el);
  });
}

/* =========================================
   BACKEND API CALLS
   ========================================= */
async function runFileAnalysis(file, config) {
  const steps = config.steps;
  const animSteps = steps.slice(0, -2).map(s => s.id);

  const formData = new FormData();
  formData.append('file', file);

  const fetchPromise = fetch(API_ANALYZE_FILE, { method: 'POST', body: formData });

  for (const stepId of animSteps) {
    const step = steps.find(s => s.id === stepId);
    await advanceStep(stepId, step.pct, steps);
  }

  let data;
  try {
    const res = await fetchPromise;
    if (!res.ok) {
      const errBody = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
      throw new Error(errBody.error || `Server error ${res.status}`);
    }
    data = await res.json();
  } catch (err) {
    processingCard.style.display = 'none';
    showBanner(`Analysis failed: ${err.message}`, 'warn');
    resetUI();
    return;
  }

  // Finish animation
  const lastTwo = steps.slice(-2);
  for (const step of lastTwo) {
    await advanceStep(step.id, step.pct, steps);
  }
  await sleep(400);

  currentAnalysis = data.result;

  // Update media meta with server response
  if (data.result.image) {
    const img = data.result.image;
    mediaMeta.innerHTML = `
      <div class="meta-item">File: <span>${img.fileName}</span></div>
      <div class="meta-item">Size: <span>${formatBytes(img.fileSize)}</span></div>
      <div class="meta-item">Dimensions: <span>${img.width} × ${img.height}px</span></div>
      <div class="meta-item">Format: <span>${img.format.toUpperCase()}</span></div>
      ${img.hasExif ? '<div class="meta-item"><span style="color:var(--green)">✓ EXIF found</span></div>' : '<div class="meta-item"><span style="color:var(--red)">✗ No EXIF</span></div>'}
      ${img.hasAlpha ? '<div class="meta-item"><span style="color:var(--cyan)">Has alpha channel</span></div>' : ''}
    `;
  } else if (data.result.media) {
    const m = data.result.media;
    mediaMeta.innerHTML = `
      <div class="meta-item">File: <span>${m.fileName}</span></div>
      <div class="meta-item">Size: <span>${formatBytes(m.fileSize)}</span></div>
      <div class="meta-item">Format: <span>${m.format}</span></div>
    `;
  }

  showResults(data.result, config);
}

async function runTextAnalysis(text, steps) {
  const animSteps = steps.slice(0, -2).map(s => s.id);

  const fetchPromise = fetch(API_ANALYZE_TEXT, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ text }),
  });

  for (const stepId of animSteps) {
    const step = steps.find(s => s.id === stepId);
    await advanceStep(stepId, step.pct, steps);
  }

  let data;
  try {
    const res = await fetchPromise;
    if (!res.ok) {
      const errBody = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
      throw new Error(errBody.error || `Server error ${res.status}`);
    }
    data = await res.json();
  } catch (err) {
    processingCard.style.display = 'none';
    showBanner(`Analysis failed: ${err.message}`, 'warn');
    resetUI();
    return;
  }

  const lastTwo = steps.slice(-2);
  for (const step of lastTwo) {
    await advanceStep(step.id, step.pct, steps);
  }
  await sleep(400);

  currentAnalysis = data.result;

  if (data.result.media) {
    mediaMeta.innerHTML = `
      <div class="meta-item">Characters: <span>${data.result.media.characterCount.toLocaleString()}</span></div>
      <div class="meta-item">Words: <span>${data.result.media.wordCount}</span></div>
      <div class="meta-item">Sentences: <span>${data.result.media.sentenceCount}</span></div>
      <div class="meta-item">Paragraphs: <span>${data.result.media.paragraphCount}</span></div>
    `;
  }

  showResults(data.result, MEDIA_CONFIG.text);
}

/* =========================================
   RENDER RESULTS
   ========================================= */
function showResults(result, config) {
  processingCard.style.display = 'none';
  scanOverlay.classList.add('done');

  /* Verdict */
  verdictBadge.className = 'verdict-badge ' + (result.isAI ? 'ai-verdict' : 'human-verdict');
  verdictIcon.textContent = result.isAI ? '🤖' : '✅';
  verdictTitle.textContent = result.isAI ? 'AI Generated' : 'Human Created';
  verdictTitle.className   = 'verdict-title ' + (result.isAI ? 'ai' : 'human');
  resultsCard.className    = 'results-card glass-card ' + (result.isAI ? 'ai-result' : 'human-result');

  /* Content type badge */
  const mediaType = result.mediaType || currentMediaType;
  const typeConfig = MEDIA_CONFIG[mediaType];
  ctbIcon.textContent = typeConfig.icon;
  ctbText.textContent = typeConfig.label;

  /* Confidence ring animation */
  const circumference = 238.76;
  const offset = circumference - (result.confidence / 100) * circumference;
  setTimeout(() => {
    confidenceArc.style.strokeDashoffset = offset;
    confidenceArc.style.transition = 'stroke-dashoffset 1.2s cubic-bezier(0.4,0,0.2,1)';
  }, 100);
  animateCounter(confidenceValue, 0, result.confidence, 1200, '%');

  /* Forensic metric bars */
  forensicMetrics.innerHTML = '';
  const metricOrder = config.metricOrder || [];

  metricOrder.forEach(({ key, label }, idx) => {
    const val   = Math.round(result.scores?.[key] ?? 0);
    const level = val >= 65 ? 'high' : val >= 35 ? 'medium' : 'low';
    const item  = document.createElement('div');
    item.className = 'metric-item';
    item.setAttribute('role', 'listitem');
    item.innerHTML = `
      <span class="metric-label">${label}</span>
      <div class="metric-bar">
        <div class="metric-fill ${level}" id="mfill-${key}" style="width:0%"></div>
      </div>
      <span class="metric-score ${level}">${val}%</span>
    `;
    forensicMetrics.appendChild(item);
    setTimeout(() => {
      const fill = document.getElementById('mfill-' + key);
      if (fill) fill.style.width = val + '%';
    }, 200 + idx * 90);
  });

  /* Explanation */
  explanationText.textContent = result.explanation ?? '';

  resultsCard.style.display   = 'flex';
  resultsCard.style.animation = 'fadeInUp 0.5s ease both';

  /* Download button */
  downloadReportBtn.onclick = () => downloadReport(result, config);
}

/* =========================================
   DOWNLOAD REPORT
   ========================================= */
function downloadReport(result, config) {
  const media = result.image || result.media || {};
  const now = new Date().toLocaleString();
  const mediaType = (result.mediaType || currentMediaType).toUpperCase();

  let mediaInfoBlock = '';
  if (result.image) {
    mediaInfoBlock = `
  File Name  : ${media.fileName ?? 'N/A'}
  File Size  : ${media.fileSize ? formatBytes(media.fileSize) : 'N/A'}
  Dimensions : ${media.width ?? '?'} × ${media.height ?? '?'} px
  Format     : ${(media.format ?? 'unknown').toUpperCase()}
  EXIF Data  : ${media.hasExif ? 'Present' : 'Not found'}
  Alpha Ch.  : ${media.hasAlpha ? 'Yes' : 'No'}`;
  } else if (result.mediaType === 'text') {
    mediaInfoBlock = `
  Characters : ${media.characterCount ?? '?'}
  Words      : ${media.wordCount ?? '?'}
  Sentences  : ${media.sentenceCount ?? '?'}
  Paragraphs : ${media.paragraphCount ?? '?'}`;
  } else {
    mediaInfoBlock = `
  File Name  : ${media.fileName ?? 'N/A'}
  File Size  : ${media.fileSize ? formatBytes(media.fileSize) : 'N/A'}
  Format     : ${media.format ?? 'UNKNOWN'}`;
  }

  const report = `
╔══════════════════════════════════════════════════════════╗
║       PIXELTRUTH v3.0 – AI CONTENT FORENSIC REPORT      ║
╚══════════════════════════════════════════════════════════╝

Report Generated : ${now}
Engine Version   : PixelTruth v3.0 (Multi-Modal Forensic API)
Content Type     : ${mediaType}

── ${mediaType} INFORMATION ──────────────────────────────────
${mediaInfoBlock}

══════════════════════════════════════════════════════════
  VERDICT   : ${result.isAI ? '🤖  AI GENERATED' : '✅  HUMAN CREATED'}
  CONFIDENCE: ${result.confidence}%
  RAW SCORE : ${result.rawScore ?? 'N/A'} / 100 (AI-likeness)
══════════════════════════════════════════════════════════

── FORENSIC BREAKDOWN ─────────────────────────────────────
${Object.entries(result.scores ?? {}).map(([k,v])=>`  ${k.padEnd(24)}: ${Math.round(v)}%  ${'█'.repeat(Math.round(v/10))}${'░'.repeat(10-Math.round(v/10))}`).join('\n')}

── ANALYSIS EXPLANATION ───────────────────────────────────
  ${result.explanation ?? ''}

── DISCLAIMER ─────────────────────────────────────────────
  This report is generated by algorithmic forensic analysis
  and should be treated as an indicator, not absolute proof.
  Results may vary based on content quality and post-processing.

══════════════════════════════════════════════════════════
     PixelTruth v3.0  |  Advanced AI Content Forensics
══════════════════════════════════════════════════════════
`.trim();

  const blob = new Blob([report], { type: 'text/plain;charset=utf-8' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.style.display = 'none';
  a.href     = url;
  a.download = `pixeltruth_${mediaType.toLowerCase()}_report_${Math.floor(Date.now()/1000)}.txt`;

  document.body.appendChild(a);
  a.click();

  setTimeout(() => {
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }, 100);
}

/* =========================================
   PROCESSING STEP ANIMATION
   ========================================= */
async function advanceStep(stepId, pct, steps) {
  document.querySelectorAll('.stage-item.active').forEach(el => {
    el.classList.remove('active');
    el.classList.add('done');
  });

  const stage = document.getElementById('stage-' + stepId);
  if (stage) {
    stage.classList.add('active');
    const s = steps.find(s => s.id === stepId);
    if (s) processingStep.textContent = s.label + '…';
  }

  progressFill.style.width = pct + '%';
  progressPct.textContent  = pct + '%';

  await sleep(240 + Math.random() * 140);
}

/* =========================================
   RESET UI
   ========================================= */
function resetUI() {
  uploadCard.style.display = currentMediaType === 'text' ? 'none' : '';
  textInputCard.style.display = currentMediaType === 'text' ? '' : 'none';
  mediaTabs.style.display = '';
  analysisPanel.classList.remove('show');
  processingCard.style.display = 'none';
  resultsCard.style.display    = 'none';
  hideAllPreviews();
  previewImage.src = '';
  previewVideo.src = '';
  audioPlayer.src  = '';
  mediaMeta.innerHTML = '';
  progressFill.style.width = '0%';
  progressPct.textContent  = '0%';
  confidenceArc.style.strokeDashoffset = '238.76';
  confidenceArc.style.transition = 'none';
  scanOverlay.classList.remove('done');
  fileInput.value   = '';
  currentAnalysis   = null;
  currentFile       = null;
}

/* =========================================
   UTILITIES
   ========================================= */
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

function formatBytes(bytes) {
  if (!bytes) return 'N/A';
  if (bytes < 1024)        return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
}

function animateCounter(el, from, to, duration, suffix = '') {
  const start = performance.now();
  const update = (now) => {
    const t = Math.min(1, (now - start) / duration);
    const ease = 1 - Math.pow(1-t, 3);
    el.textContent = Math.round(from + (to - from) * ease) + suffix;
    if (t < 1) requestAnimationFrame(update);
  };
  requestAnimationFrame(update);
}

/* =========================================
   SCROLL ANIMATION
   ========================================= */
const observer = new IntersectionObserver((entries) => {
  entries.forEach(e => {
    if (e.isIntersecting) {
      e.target.style.opacity = '1';
      e.target.style.transform = 'translateY(0)';
    }
  });
}, { threshold: 0.1 });

document.querySelectorAll('.how-card').forEach(el => {
  el.style.opacity = '0';
  el.style.transform = 'translateY(32px)';
  el.style.transition = 'opacity 0.6s ease, transform 0.6s ease';
  observer.observe(el);
});
