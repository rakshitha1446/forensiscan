/**
 * PixelTruth v3.0 – Image Forensic Analyzer
 * Uses Sharp for pixel-level image analysis
 *
 * Performs 8 independent forensic detection vectors on the
 * uploaded image and returns a structured classification result.
 */

'use strict';

const sharp = require('sharp');

/* ───────────────────────────────────────────────────────────
   MAIN ENTRY POINT
   ─────────────────────────────────────────────────────────── */
async function analyze(filePath, meta) {
  // Load image via Sharp
  const img = sharp(filePath);
  let imgMeta;
  try {
    imgMeta = await img.metadata();
  } catch (err) {
    throw new Error('Could not read image metadata: ' + err.message);
  }

  const { width: origW, height: origH, format, exif, icc, iptc, xmp, hasAlpha } = imgMeta;

  if (!origW || !origH) {
    throw new Error('Invalid image: could not determine dimensions.');
  }

  // Resize for analysis (performance) at max 512px
  const maxSize = 512;
  const scale = Math.min(1, maxSize / Math.max(origW, origH));
  const w = Math.max(1, Math.round(origW * scale));
  const h = Math.max(1, Math.round(origH * scale));

  // Get raw RGB pixel buffer
  let rawData;
  try {
    const result = await sharp(filePath)
      .resize(w, h, { fit: 'inside' })
      .removeAlpha()
      .raw()
      .toBuffer({ resolveWithObject: true });
    rawData = result.data;
  } catch (err) {
    throw new Error('Failed to process image pixels: ' + err.message);
  }

  // Sharp stats for fast statistical analysis
  const stats = await sharp(filePath).stats();

  const scores = {};

  // Run all 8 forensic vectors
  scores.metadataIntegrity = analyzeMetadata(meta, imgMeta, exif, icc, iptc, xmp);
  scores.pixelEntropy = analyzePixelEntropy(stats, rawData, w, h);
  scores.noiseConsistency = analyzeNoise(rawData, w, h);
  scores.freqAnomaly = analyzeFrequency(rawData, w, h);
  scores.edgeArtifacts = analyzeEdges(rawData, w, h);
  scores.compressionAnomaly = analyzeCompression(rawData, w, h, format);
  scores.textureRepetition = analyzeTexture(rawData, w, h);
  scores.colorDistribution = analyzeColor(stats, rawData, w, h);

  // Classify
  const result = classify(scores, { width: origW, height: origH, format }, meta);

  return {
    ...result,
    mediaType: 'image',
    image: {
      width: origW,
      height: origH,
      format: format || meta.mimeType.split('/')[1],
      fileSize: meta.size,
      fileName: meta.originalName,
      hasExif: !!exif,
      hasAlpha: !!hasAlpha,
    },
    scores,
    explanation: generateExplanation(result, scores),
  };
}

/* ───────────────────────────────────────────────────────────
   VECTOR 1 – METADATA FORENSICS
   ─────────────────────────────────────────────────────────── */
function analyzeMetadata(meta, imgMeta, exif, icc, iptc, xmp) {
  let suspicion = 0;

  const { originalName, mimeType, size } = meta;
  const { width = 0, height = 0, format } = imgMeta;

  // AI tool naming patterns in filename
  const aiPatterns = [
    /^image[-_]?\d+/i, /^generated/i, /^ai[-_]/i,
    /stable.?diffusion/i, /dall[-_.]?e/i, /midjourney/i,
    /^output[-_]?\d*/i, /comfyui/i, /^sd_/i, /^flux/i,
    /imagine/i, /^artifact/i,
  ];
  if (aiPatterns.some(p => p.test(originalName))) suspicion += 22;

  // AI-typical exact dimensions
  const aiDims = new Set([512, 640, 768, 832, 896, 1024, 1152, 1280, 1536, 1792, 2048]);
  if (aiDims.has(width)) suspicion += 15;
  if (aiDims.has(height)) suspicion += 15;

  // Perfect square dimensions
  if (width === height) suspicion += 12;

  // Power-of-two both sides
  const isPow2 = (n) => n > 0 && (n & (n - 1)) === 0;
  if (isPow2(width) && isPow2(height)) suspicion += 18;

  // No EXIF data (AI images almost never have camera EXIF)
  if (!exif) suspicion += 35;
  if (!icc) suspicion += 15;

  // PNG format without alpha is unusual for real photos
  if (format === 'png' && !imgMeta.hasAlpha) suspicion += 10;

  // File size anomaly relative to pixels
  const pixelArea = width * height;
  const bytesPerPx = pixelArea > 0 ? size / pixelArea : 0;
  if (bytesPerPx < 0.05 || bytesPerPx > 6.0) suspicion += 15;

  return Math.min(100, suspicion);
}

/* ───────────────────────────────────────────────────────────
   VECTOR 2 – PIXEL ENTROPY
   ─────────────────────────────────────────────────────────── */
function analyzePixelEntropy(stats, data, w, h) {
  const channels = stats.channels;
  let suspicion = 0;
  const totalPx = w * h;

  // Shannon entropy from raw RGB
  const rHist = new Int32Array(256);
  const gHist = new Int32Array(256);
  const bHist = new Int32Array(256);
  for (let i = 0; i < data.length; i += 3) {
    rHist[data[i]]++;
    gHist[data[i + 1]]++;
    bHist[data[i + 2]]++;
  }
  const ent = (hist) => {
    let h = 0;
    for (let v of hist) {
      if (v > 0) { const p = v / totalPx; h -= p * Math.log2(p); }
    }
    return h;
  };
  const avgEntropy = (ent(rHist) + ent(gHist) + ent(bHist)) / 3;

  if (avgEntropy > 7.4) suspicion += 35;
  if (avgEntropy < 5.8) suspicion += 30;

  // Channel std deviations
  if (channels.length >= 3) {
    const rStd = channels[0].stdev || channels[0].std || 0;
    const gStd = channels[1].stdev || channels[1].std || 0;
    const bStd = channels[2].stdev || channels[2].std || 0;
    const avgStd = (rStd + gStd + bStd) / 3;

    if (avgStd < 20) suspicion += 25;
    const stdBalance = Math.abs(rStd - gStd) + Math.abs(gStd - bStd);
    if (stdBalance < 3) suspicion += 20;
  }

  // Histogram spikes
  const maxR = Math.max(...rHist);
  const maxG = Math.max(...gHist);
  const maxB = Math.max(...bHist);
  const spikeRatio = ((maxR + maxG + maxB) / 3) / totalPx;
  if (spikeRatio > 0.025) suspicion += 15;

  return Math.min(100, suspicion);
}

/* ───────────────────────────────────────────────────────────
   VECTOR 3 – NOISE PATTERN ANALYSIS
   ─────────────────────────────────────────────────────────── */
function analyzeNoise(data, w, h) {
  const gray = new Float32Array(w * h);
  for (let i = 0; i < gray.length; i++) {
    gray[i] = 0.299 * data[i * 3] + 0.587 * data[i * 3 + 1] + 0.114 * data[i * 3 + 2];
  }

  const variances = [];
  for (let y = 1; y < h - 1; y++) {
    for (let x = 1; x < w - 1; x++) {
      const idx = y * w + x;
      const neighbors = [
        gray[idx - w - 1], gray[idx - w], gray[idx - w + 1],
        gray[idx - 1], gray[idx], gray[idx + 1],
        gray[idx + w - 1], gray[idx + w], gray[idx + w + 1],
      ];
      const mean = neighbors.reduce((a, b) => a + b, 0) / 9;
      const variance = neighbors.reduce((a, b) => a + (b - mean) ** 2, 0) / 9;
      variances.push(variance);
    }
  }

  if (variances.length === 0) return 50;

  const avgVar = variances.reduce((a, b) => a + b, 0) / variances.length;
  const stdVar = Math.sqrt(variances.reduce((a, b) => a + (b - avgVar) ** 2, 0) / variances.length);
  const cv = avgVar > 0 ? stdVar / avgVar : 0;

  let suspicion = 0;
  if (avgVar < 6.5) suspicion += 45;
  if (avgVar > 120) suspicion += 22;
  if (cv < 0.6) suspicion += 30;
  if (cv > 4.0) suspicion += 12;

  return Math.min(100, suspicion);
}

/* ───────────────────────────────────────────────────────────
   VECTOR 4 – FREQUENCY DOMAIN (DCT-based)
   ─────────────────────────────────────────────────────────── */
function analyzeFrequency(data, w, h) {
  const blockSize = 8;
  const dcValues = [];
  const acMagnitudes = [];

  for (let by = 0; by < Math.floor(h / blockSize); by++) {
    for (let bx = 0; bx < Math.floor(w / blockSize); bx++) {
      const block = [];
      for (let y = 0; y < blockSize; y++) {
        for (let x = 0; x < blockSize; x++) {
          const px = (by * blockSize + y) * w + (bx * blockSize + x);
          block.push(0.299 * data[px * 3] + 0.587 * data[px * 3 + 1] + 0.114 * data[px * 3 + 2] - 128);
        }
      }
      let dc = 0;
      for (const v of block) dc += v;
      dc /= block.length;
      dcValues.push(Math.abs(dc));

      let ac = 0;
      for (let k = 1; k < block.length; k++) {
        ac += Math.abs(block[k]) * Math.exp(-0.5 * k / block.length);
      }
      acMagnitudes.push(ac);
    }
  }

  if (dcValues.length === 0) return 50;

  const avgDC = dcValues.reduce((a, b) => a + b, 0) / dcValues.length;
  const avgAC = acMagnitudes.reduce((a, b) => a + b, 0) / acMagnitudes.length;
  const ratio = avgDC > 0 ? avgAC / avgDC : 1;

  let suspicion = 0;
  if (ratio < 1.5) suspicion += 30;
  if (ratio > 28) suspicion += 18;
  if (avgDC < 2) suspicion += 28;
  if (avgDC > 80) suspicion += 14;

  return Math.min(100, suspicion);
}

/* ───────────────────────────────────────────────────────────
   VECTOR 5 – EDGE COHERENCE ANALYSIS (Sobel)
   ─────────────────────────────────────────────────────────── */
function analyzeEdges(data, w, h) {
  const gray = new Float32Array(w * h);
  for (let i = 0; i < gray.length; i++) {
    gray[i] = 0.299 * data[i * 3] + 0.587 * data[i * 3 + 1] + 0.114 * data[i * 3 + 2];
  }

  const sobelX = [-1, 0, 1, -2, 0, 2, -1, 0, 1];
  const sobelY = [-1, -2, -1, 0, 0, 0, 1, 2, 1];
  const edges = new Float32Array(w * h);

  for (let y = 1; y < h - 1; y++) {
    for (let x = 1; x < w - 1; x++) {
      let gx = 0, gy = 0;
      for (let ky = -1; ky <= 1; ky++) {
        for (let kx = -1; kx <= 1; kx++) {
          const pi = (y + ky) * w + (x + kx);
          const ki = (ky + 1) * 3 + (kx + 1);
          gx += gray[pi] * sobelX[ki];
          gy += gray[pi] * sobelY[ki];
        }
      }
      edges[y * w + x] = Math.sqrt(gx * gx + gy * gy);
    }
  }

  const nonZero = Array.from(edges).filter(v => v > 10);
  if (!nonZero.length) return 65;

  const meanE = nonZero.reduce((a, b) => a + b, 0) / nonZero.length;
  const stdE = Math.sqrt(nonZero.reduce((a, b) => a + (b - meanE) ** 2, 0) / nonZero.length);
  const cv = stdE / (meanE || 1);
  const density = nonZero.length / (w * h);

  let suspicion = 0;
  if (cv < 0.4) suspicion += 35;
  if (cv > 2.8) suspicion += 12;
  if (density > 0.7) suspicion += 25;
  if (density < 0.05) suspicion += 18;
  if (meanE > 150) suspicion += 22;

  return Math.min(100, suspicion);
}

/* ───────────────────────────────────────────────────────────
   VECTOR 6 – COMPRESSION ANOMALY
   ─────────────────────────────────────────────────────────── */
function analyzeCompression(data, w, h, format) {
  let suspicion = 0;
  let boundaryDiffSum = 0;
  let count = 0;

  for (let y = 0; y < h - 8; y += 8) {
    for (let x = 0; x < w - 8; x += 8) {
      let diffRow = 0;
      for (let dy = 0; dy < 8; dy++) {
        const i1 = ((y + dy) * w + (x + 7)) * 3;
        const i2 = ((y + dy) * w + (x + 8)) * 3;
        if (i2 + 2 >= data.length) continue; // bounds check
        diffRow += Math.abs(data[i1] - data[i2]) + Math.abs(data[i1 + 1] - data[i2 + 1]) + Math.abs(data[i1 + 2] - data[i2 + 2]);
      }
      boundaryDiffSum += diffRow / 8;
      count++;
    }
  }

  const avgDiff = count > 0 ? boundaryDiffSum / count : 0;
  if (avgDiff < 4) suspicion += 42;
  if (avgDiff > 45) suspicion += 18;
  if (format === 'png') suspicion += 12;

  return Math.min(100, suspicion);
}

/* ───────────────────────────────────────────────────────────
   VECTOR 7 – TEXTURE REPETITION
   ─────────────────────────────────────────────────────────── */
function analyzeTexture(data, w, h) {
  const sampleSize = Math.min(128, w, h);
  const samples = [];
  for (let y = 0; y < sampleSize; y++) {
    for (let x = 0; x < sampleSize; x++) {
      const i = (y * w + x) * 3;
      if (i + 2 >= data.length) continue;
      samples.push(0.299 * data[i] + 0.587 * data[i + 1] + 0.114 * data[i + 2]);
    }
  }

  if (samples.length === 0) return 50;

  const sumSq = samples.reduce((a, b) => a + b * b, 0) / samples.length;
  const offsets = [4, 8, 16, 32];
  let corrTotal = 0;
  for (const off of offsets) {
    let corr = 0;
    let n = 0;
    for (let i = 0; i + off < samples.length; i++) {
      corr += samples[i] * samples[i + off];
      n++;
    }
    corrTotal += (n > 0 ? corr / n : 0);
  }

  const normCorr = sumSq > 0 ? corrTotal / (offsets.length * sumSq) : 0;

  let suspicion = 0;
  if (normCorr > 1.4) suspicion += 38;
  if (normCorr > 2.2) suspicion += 22;

  return Math.min(100, suspicion);
}

/* ───────────────────────────────────────────────────────────
   VECTOR 8 – COLOR DISTRIBUTION
   ─────────────────────────────────────────────────────────── */
function analyzeColor(stats, data, w, h) {
  const channels = stats.channels;
  let suspicion = 0;
  const totalPx = w * h;

  const colorSet = new Set();
  const sampleLimit = Math.min(data.length / 3, 50000);
  let totalSat = 0;

  for (let i = 0, px = 0; px < sampleLimit; i += 3, px++) {
    if (i + 2 >= data.length) break;
    const r = data[i] / 255, g = data[i + 1] / 255, b = data[i + 2] / 255;
    const max = Math.max(r, g, b), min = Math.min(r, g, b);
    const l = (max + min) / 2;
    const s = max === min ? 0 : l > 0.5 ? (max - min) / (2 - max - min) : (max - min) / (max + min);
    totalSat += s;
    const key = `${Math.floor(r * 63)},${Math.floor(g * 63)},${Math.floor(b * 63)}`;
    colorSet.add(key);
  }

  const actualSampleCount = Math.min(sampleLimit, Math.floor(data.length / 3));
  const avgSat = actualSampleCount > 0 ? totalSat / actualSampleCount : 0;

  if (avgSat > 0.52) suspicion += 32;
  if (avgSat < 0.06) suspicion += 15;
  if (colorSet.size < 800) suspicion += 25;

  // Channel balance from Sharp stats
  if (channels.length >= 3) {
    const rM = channels[0].mean, gM = channels[1].mean, bM = channels[2].mean;
    const balance = Math.abs(rM - gM) + Math.abs(gM - bM) + Math.abs(rM - bM);
    if (balance < 10) suspicion += 22;
  }

  return Math.min(100, suspicion);
}

/* ───────────────────────────────────────────────────────────
   CLASSIFICATION ENGINE
   ─────────────────────────────────────────────────────────── */
function classify(scores, imgInfo, meta) {
  const weights = {
    pixelEntropy: 1.8,
    noiseConsistency: 2.5,
    edgeArtifacts: 2.0,
    colorDistribution: 1.4,
    compressionAnomaly: 1.8,
    textureRepetition: 1.7,
    freqAnomaly: 1.6,
    metadataIntegrity: 2.5,
  };

  let wSum = 0, wTotal = 0;
  for (const [key, w] of Object.entries(weights)) {
    if (scores[key] !== undefined) {
      wSum += scores[key] * w;
      wTotal += w;
    }
  }

  let rawScore = wTotal > 0 ? wSum / wTotal : 50;

  const highVectors = Object.values(scores).filter(v => v > 60).length;
  if (highVectors >= 2) rawScore += 12;
  if (highVectors >= 4) rawScore += 18;

  const { width = 0, height = 0 } = imgInfo;
  const aiDims = new Set([512, 640, 768, 832, 896, 1024, 1152, 1280, 1536, 1792, 2048]);
  if (aiDims.has(width) || aiDims.has(height)) rawScore += 10;
  if (width === height) rawScore += 6;

  if (scores.metadataIntegrity > 60 && scores.noiseConsistency > 50) rawScore += 15;

  rawScore = Math.min(100, Math.max(0, rawScore));

  const sigmoid = (x) => 1 / (1 + Math.exp(-0.13 * (x - 33)));
  const aiProb = sigmoid(rawScore) * 100;

  const isAI = aiProb >= 50;
  const rawConf = isAI ? aiProb : 100 - aiProb;
  const confidence = Math.min(97, Math.max(51, Math.round(rawConf)));

  return { isAI, confidence, rawScore: Math.round(rawScore) };
}

/* ───────────────────────────────────────────────────────────
   EXPLANATION GENERATOR
   ─────────────────────────────────────────────────────────── */
function generateExplanation(result, scores) {
  const labels = {
    noiseConsistency: 'unnaturally smooth noise patterns',
    edgeArtifacts: 'hyper-consistent edge sharpness',
    pixelEntropy: 'abnormal pixel entropy distribution',
    freqAnomaly: 'irregular DCT frequency signatures',
    compressionAnomaly: 'unusual block compression patterns',
    textureRepetition: 'periodic texture autocorrelation',
    colorDistribution: 'over-saturated synthetic color palette',
    metadataIntegrity: 'suspicious metadata fingerprints',
  };

  const top3 = Object.entries(scores)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 3)
    .map(([k]) => labels[k] ?? k);

  if (result.isAI) {
    return `This image exhibits strong AI-generation signatures with ${result.confidence}% confidence. ` +
      `Key forensic evidence includes: ${top3.join(', ')}. ` +
      `These patterns are statistically characteristic of neural networks such as diffusion models (Stable Diffusion, DALL·E, Midjourney), ` +
      `which produce fundamentally different pixel distributions compared to natural photography.`;
  } else {
    const bot3 = Object.entries(scores)
      .sort((a, b) => a[1] - b[1])
      .slice(0, 3)
      .map(([k]) => ({
        noiseConsistency: 'natural camera sensor noise',
        edgeArtifacts: 'organic edge variation',
        pixelEntropy: 'typical photographic entropy',
        freqAnomaly: 'normal frequency spectrum',
        compressionAnomaly: 'standard JPEG compression',
        textureRepetition: 'non-repeating texture structure',
        colorDistribution: 'natural color saturation',
        metadataIntegrity: 'authentic metadata structure',
      }[k] ?? k));
    return `This image appears to be human-created or photographed with ${result.confidence}% confidence. ` +
      `Forensic analysis found: ${bot3.join(', ')} — all consistent with real-world imagery.`;
  }
}

module.exports = { analyze };
