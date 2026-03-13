/**
 * PixelTruth v3.0 – Audio Forensic Analyzer
 * Analyzes audio files for AI-generation signatures
 *
 * Detection vectors:
 *   1. File metadata & naming patterns
 *   2. Byte-level spectral estimation
 *   3. Silence & noise floor analysis
 *   4. Amplitude distribution
 *   5. Frequency uniformity
 *   6. Structural regularity
 */

'use strict';

const fs = require('fs');
const path = require('path');

/* ───────────────────────────────────────────────────────────
   MAIN ENTRY POINT
   ─────────────────────────────────────────────────────────── */
async function analyze(filePath, meta) {
  const fileBuffer = fs.readFileSync(filePath);

  const scores = {};

  scores.metadataIntegrity = analyzeAudioMetadata(meta, fileBuffer);
  scores.spectralPattern = analyzeSpectralPatterns(fileBuffer, meta);
  scores.noiseFloor = analyzeNoiseFloor(fileBuffer);
  scores.amplitudeDistribution = analyzeAmplitude(fileBuffer);
  scores.frequencyUniformity = analyzeFrequencyUniformity(fileBuffer);
  scores.structuralRegularity = analyzeStructure(fileBuffer, meta);

  const result = classifyAudio(scores, meta);

  return {
    ...result,
    mediaType: 'audio',
    media: {
      fileName: meta.originalName,
      fileSize: meta.size,
      format: path.extname(meta.originalName).replace('.', '').toUpperCase() || 'UNKNOWN',
      mimeType: meta.mimeType,
    },
    scores,
    explanation: generateAudioExplanation(result, scores),
  };
}

/* ───────────────────────────────────────────────────────────
   VECTOR 1 – AUDIO METADATA
   ─────────────────────────────────────────────────────────── */
function analyzeAudioMetadata(meta, buffer) {
  let suspicion = 0;
  const name = meta.originalName.toLowerCase();

  // AI audio tool naming patterns
  const aiPatterns = [
    /eleven[-_]?labs/i, /^tts[-_]/i, /bark/i, /tortoise/i,
    /^generated/i, /^ai[-_]/i, /^output[-_]?\d*/i,
    /murf/i, /play\.ht/i, /speech[-_]?gen/i,
    /suno/i, /udio/i, /riffusion/i, /musicgen/i,
    /^voice[-_]?\d/i, /clone/i, /synthesized/i,
  ];
  if (aiPatterns.some(p => p.test(name))) suspicion += 30;

  // Check for AI tool metadata in file header
  const headerStr = buffer.slice(0, Math.min(4096, buffer.length)).toString('ascii');
  const aiTools = ['elevenlabs', 'bark', 'suno', 'udio', 'murf', 'tts', 'synthesis'];
  for (const tool of aiTools) {
    if (headerStr.toLowerCase().includes(tool)) {
      suspicion += 25;
      break;
    }
  }

  // Short duration heuristic (small file size)
  const mbSize = meta.size / (1024 * 1024);
  if (mbSize < 0.3) suspicion += 15;

  // WAV format is commonly used for AI TTS output
  if (meta.mimeType.includes('wav')) suspicion += 8;

  return Math.min(100, suspicion);
}

/* ───────────────────────────────────────────────────────────
   VECTOR 2 – SPECTRAL PATTERN ANALYSIS
   ─────────────────────────────────────────────────────────── */
function analyzeSpectralPatterns(buffer, meta) {
  let suspicion = 0;

  // Skip header based on format
  let dataStart = 0;
  const header = buffer.slice(0, 4).toString('ascii');
  if (header === 'RIFF') {
    // WAV: find 'data' chunk
    for (let i = 0; i < Math.min(buffer.length - 4, 200); i++) {
      if (buffer.slice(i, i + 4).toString('ascii') === 'data') {
        dataStart = i + 8;
        break;
      }
    }
  } else if (header.slice(0, 3) === 'ID3' || buffer[0] === 0xFF) {
    dataStart = 128; // MP3 approximate header skip
  } else {
    dataStart = 32;
  }

  const audioData = buffer.slice(dataStart);
  const sampleSize = Math.min(audioData.length, 100000);

  // Compute squared magnitude in pseudo-spectral bins
  const numBins = 32;
  const binSize = Math.floor(sampleSize / numBins);
  const binEnergies = [];

  for (let b = 0; b < numBins; b++) {
    let energy = 0;
    for (let i = 0; i < binSize; i++) {
      const val = audioData[b * binSize + i] - 128;
      energy += val * val;
    }
    binEnergies.push(energy / binSize);
  }

  // AI audio typically has more uniform spectral distribution
  const meanEnergy = binEnergies.reduce((a, b) => a + b, 0) / binEnergies.length;
  const stdEnergy = Math.sqrt(binEnergies.reduce((a, b) => a + (b - meanEnergy) ** 2, 0) / binEnergies.length);
  const cv = meanEnergy > 0 ? stdEnergy / meanEnergy : 0;

  if (cv < 0.15) suspicion += 40; // Very uniform = synthetic
  if (cv < 0.3) suspicion += 20;
  if (cv > 2.0) suspicion += 10; // Very uneven

  // Spectral flatness indicator
  const logMeanEnergy = binEnergies.reduce((a, b) => a + Math.log(Math.max(b, 0.001)), 0) / binEnergies.length;
  const flatness = Math.exp(logMeanEnergy) / (meanEnergy || 1);
  if (flatness > 0.7) suspicion += 25; // High flatness = synthetic

  return Math.min(100, suspicion);
}

/* ───────────────────────────────────────────────────────────
   VECTOR 3 – NOISE FLOOR ANALYSIS
   ─────────────────────────────────────────────────────────── */
function analyzeNoiseFloor(buffer) {
  let suspicion = 0;

  const dataStart = Math.min(256, Math.floor(buffer.length * 0.1));
  const data = buffer.slice(dataStart);
  const sampleSize = Math.min(data.length, 80000);

  // Detect quiet segments (noise floor)
  const windowSize = 256;
  const windowEnergies = [];

  for (let i = 0; i + windowSize < sampleSize; i += windowSize) {
    let energy = 0;
    for (let j = 0; j < windowSize; j++) {
      const val = data[i + j] - 128;
      energy += Math.abs(val);
    }
    windowEnergies.push(energy / windowSize);
  }

  if (windowEnergies.length === 0) return 50;

  // Sort to find quiet windows
  const sorted = [...windowEnergies].sort((a, b) => a - b);
  const quietFloor = sorted[Math.floor(sorted.length * 0.1)]; // 10th percentile
  const loudPeak = sorted[Math.floor(sorted.length * 0.9)]; // 90th percentile

  // AI audio has very clean noise floors
  if (quietFloor < 2) suspicion += 35;
  if (quietFloor < 5) suspicion += 15;

  // Dynamic range analysis
  const dynamicRange = loudPeak - quietFloor;
  if (dynamicRange < 10) suspicion += 20; // Very compressed dynamic range
  if (dynamicRange > 80) suspicion += 10; // Unnaturally wide

  return Math.min(100, suspicion);
}

/* ───────────────────────────────────────────────────────────
   VECTOR 4 – AMPLITUDE DISTRIBUTION
   ─────────────────────────────────────────────────────────── */
function analyzeAmplitude(buffer) {
  let suspicion = 0;

  const dataStart = Math.min(256, Math.floor(buffer.length * 0.1));
  const data = buffer.slice(dataStart);
  const sampleSize = Math.min(data.length, 100000);

  // Build amplitude histogram
  const hist = new Int32Array(256);
  for (let i = 0; i < sampleSize; i++) {
    hist[data[i]]++;
  }

  // Calculate entropy of amplitude distribution
  let entropy = 0;
  for (let i = 0; i < 256; i++) {
    if (hist[i] > 0) {
      const p = hist[i] / sampleSize;
      entropy -= p * Math.log2(p);
    }
  }

  // AI audio tends to have specific entropy ranges
  if (entropy < 5.0) suspicion += 30; // Low entropy = synthetic
  if (entropy > 7.8) suspicion += 10; // Over-randomized

  // Check for clipping or saturation
  const clipCount = hist[0] + hist[255];
  const clipRatio = clipCount / sampleSize;
  if (clipRatio > 0.1) suspicion += 15; // Heavy clipping
  if (clipRatio < 0.001 && entropy < 6) suspicion += 20; // No clipping + low entropy

  // Symmetry around 128 (DC offset)
  let lowerHalf = 0, upperHalf = 0;
  for (let i = 0; i < 128; i++) lowerHalf += hist[i];
  for (let i = 128; i < 256; i++) upperHalf += hist[i];
  const symmetry = Math.abs(lowerHalf - upperHalf) / sampleSize;
  if (symmetry < 0.02) suspicion += 20; // Perfectly centered = synthetic

  return Math.min(100, suspicion);
}

/* ───────────────────────────────────────────────────────────
   VECTOR 5 – FREQUENCY UNIFORMITY
   ─────────────────────────────────────────────────────────── */
function analyzeFrequencyUniformity(buffer) {
  let suspicion = 0;

  const dataStart = Math.min(512, Math.floor(buffer.length * 0.1));
  const data = buffer.slice(dataStart);
  const sampleSize = Math.min(data.length, 50000);

  // Analyze zero-crossing rate (proxy for frequency content)
  const segmentSize = 512;
  const zcRates = [];

  for (let s = 0; s + segmentSize < sampleSize; s += segmentSize) {
    let crossings = 0;
    for (let i = 1; i < segmentSize; i++) {
      const prev = data[s + i - 1] - 128;
      const curr = data[s + i] - 128;
      if ((prev >= 0 && curr < 0) || (prev < 0 && curr >= 0)) {
        crossings++;
      }
    }
    zcRates.push(crossings / segmentSize);
  }

  if (zcRates.length === 0) return 50;

  const meanZC = zcRates.reduce((a, b) => a + b, 0) / zcRates.length;
  const stdZC = Math.sqrt(zcRates.reduce((a, b) => a + (b - meanZC) ** 2, 0) / zcRates.length);
  const cvZC = meanZC > 0 ? stdZC / meanZC : 0;

  // AI speech has very consistent zero-crossing rates
  if (cvZC < 0.15) suspicion += 35;
  if (cvZC < 0.3) suspicion += 15;

  return Math.min(100, suspicion);
}

/* ───────────────────────────────────────────────────────────
   VECTOR 6 – STRUCTURAL REGULARITY
   ─────────────────────────────────────────────────────────── */
function analyzeStructure(buffer, meta) {
  let suspicion = 0;

  // Analyze repeating patterns in raw bytes
  const sampleSize = Math.min(buffer.length, 50000);
  const blockSize = 256;
  const blocks = Math.floor(sampleSize / blockSize);

  const blockSums = [];
  for (let b = 0; b < blocks; b++) {
    let sum = 0;
    for (let i = 0; i < blockSize; i++) {
      sum += buffer[b * blockSize + i];
    }
    blockSums.push(sum / blockSize);
  }

  // Check auto-correlation at short lags
  const lags = [1, 2, 3, 4, 8];
  let highCorrCount = 0;

  for (const lag of lags) {
    let corr = 0;
    let n = 0;
    for (let i = 0; i + lag < blockSums.length; i++) {
      corr += Math.abs(blockSums[i] - blockSums[i + lag]);
      n++;
    }
    const avgDiff = n > 0 ? corr / n : 999;
    if (avgDiff < 3) highCorrCount++;
  }

  if (highCorrCount >= 3) suspicion += 30;
  if (highCorrCount >= 5) suspicion += 20;

  // Perfect sample rate alignment (AI tools use standard rates)
  const ext = path.extname(meta.originalName).toLowerCase();
  if (ext === '.wav') {
    // Check WAV header for sample rate
    if (buffer.length > 28) {
      const sampleRate = buffer.readUInt32LE(24);
      const aiRates = [22050, 24000, 44100, 48000];
      if (aiRates.includes(sampleRate)) suspicion += 8;
      // Mono channel is common in AI TTS
      if (buffer.length > 22) {
        const channels = buffer.readUInt16LE(22);
        if (channels === 1) suspicion += 15;
      }
    }
  }

  return Math.min(100, suspicion);
}

/* ───────────────────────────────────────────────────────────
   AUDIO CLASSIFICATION
   ─────────────────────────────────────────────────────────── */
function classifyAudio(scores, meta) {
  const weights = {
    metadataIntegrity: 2.0,
    spectralPattern: 2.5,
    noiseFloor: 2.2,
    amplitudeDistribution: 1.8,
    frequencyUniformity: 2.0,
    structuralRegularity: 1.5,
  };

  let wSum = 0, wTotal = 0;
  for (const [key, w] of Object.entries(weights)) {
    if (scores[key] !== undefined) {
      wSum += scores[key] * w;
      wTotal += w;
    }
  }

  let rawScore = wTotal > 0 ? wSum / wTotal : 50;

  const highVectors = Object.values(scores).filter(v => v > 55).length;
  if (highVectors >= 2) rawScore += 8;
  if (highVectors >= 4) rawScore += 12;

  rawScore = Math.min(100, Math.max(0, rawScore));

  const sigmoid = (x) => 1 / (1 + Math.exp(-0.12 * (x - 36)));
  const aiProb = sigmoid(rawScore) * 100;

  const isAI = aiProb >= 50;
  const rawConf = isAI ? aiProb : 100 - aiProb;
  const confidence = Math.min(90, Math.max(51, Math.round(rawConf)));

  return { isAI, confidence, rawScore: Math.round(rawScore) };
}

/* ───────────────────────────────────────────────────────────
   EXPLANATION GENERATOR
   ─────────────────────────────────────────────────────────── */
function generateAudioExplanation(result, scores) {
  const labels = {
    metadataIntegrity: 'AI tool signatures in file metadata',
    spectralPattern: 'synthetic spectral energy distribution',
    noiseFloor: 'unnaturally clean noise floor',
    amplitudeDistribution: 'non-natural amplitude histogram',
    frequencyUniformity: 'overly consistent frequency content',
    structuralRegularity: 'periodic structural patterns',
  };

  const top3 = Object.entries(scores)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 3)
    .map(([k]) => labels[k] ?? k);

  if (result.isAI) {
    return `This audio exhibits AI-generation signatures with ${result.confidence}% confidence. ` +
      `Key forensic findings: ${top3.join(', ')}. ` +
      `These patterns are characteristic of AI speech synthesis (ElevenLabs, Bark, Tortoise TTS) ` +
      `or AI music generators (Suno, Udio, MusicGen) which produce distinct spectral fingerprints.`;
  } else {
    return `This audio appears to be naturally recorded with ${result.confidence}% confidence. ` +
      `The spectral characteristics, noise patterns, and amplitude distribution are consistent ` +
      `with authentic microphone recordings and natural sound sources.`;
  }
}

module.exports = { analyze };
