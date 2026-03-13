/**
 * PixelTruth v3.0 – Text Forensic Analyzer
 * Analyzes text content for AI-generation signatures
 *
 * Detection vectors:
 *   1. Burstiness analysis (sentence length variation)
 *   2. Vocabulary diversity (TTR, hapax legomena)
 *   3. Perplexity proxy (character-level predictability)
 *   4. Repetition patterns (phrase / n-gram frequency)
 *   5. Structural patterns (paragraph uniformity)
 *   6. Linguistic markers (hedging, filler patterns)
 */

'use strict';

/* ───────────────────────────────────────────────────────────
   MAIN ENTRY POINT
   ─────────────────────────────────────────────────────────── */
function analyze(text) {
  if (!text || text.length < 20) {
    throw new Error('Text must be at least 20 characters long.');
  }

  const scores = {};

  scores.burstiness = analyzeBurstiness(text);
  scores.vocabularyDiversity = analyzeVocabulary(text);
  scores.perplexityProxy = analyzePerplexity(text);
  scores.repetitionPatterns = analyzeRepetition(text);
  scores.structuralUniformity = analyzeStructure(text);
  scores.linguisticMarkers = analyzeLinguisticMarkers(text);

  const result = classifyText(scores, text);

  const wordCount = text.split(/\s+/).filter(w => w.length > 0).length;
  const sentenceCount = text.split(/[.!?]+/).filter(s => s.trim().length > 0).length;
  const paragraphCount = text.split(/\n\s*\n/).filter(p => p.trim().length > 0).length;

  return {
    ...result,
    mediaType: 'text',
    media: {
      characterCount: text.length,
      wordCount,
      sentenceCount,
      paragraphCount,
    },
    scores,
    explanation: generateTextExplanation(result, scores),
  };
}

/* ───────────────────────────────────────────────────────────
   VECTOR 1 – BURSTINESS (Sentence Length Variation)
   ─────────────────────────────────────────────────────────── */
function analyzeBurstiness(text) {
  let suspicion = 0;

  const sentences = text.split(/[.!?]+/).filter(s => s.trim().length > 0);
  if (sentences.length < 3) return 50;

  const lengths = sentences.map(s => s.trim().split(/\s+/).length);
  const mean = lengths.reduce((a, b) => a + b, 0) / lengths.length;
  const std = Math.sqrt(lengths.reduce((a, b) => a + (b - mean) ** 2, 0) / lengths.length);
  const cv = mean > 0 ? std / mean : 0;

  // AI text has LOW burstiness (consistent sentence lengths)
  // Human text has HIGH burstiness (variable sentence lengths)
  if (cv < 0.25) suspicion += 45; // Very uniform
  if (cv < 0.35) suspicion += 25;
  if (cv < 0.45) suspicion += 10;

  // AI tends to avoid very short sentences
  const shortSentences = lengths.filter(l => l <= 3).length;
  const shortRatio = shortSentences / lengths.length;
  if (shortRatio < 0.05 && sentences.length > 5) suspicion += 15;

  // AI also avoids very long sentences
  const longSentences = lengths.filter(l => l > 30).length;
  const longRatio = longSentences / lengths.length;
  if (longRatio < 0.02 && sentences.length > 5) suspicion += 10;

  return Math.min(100, suspicion);
}

/* ───────────────────────────────────────────────────────────
   VECTOR 2 – VOCABULARY DIVERSITY
   ─────────────────────────────────────────────────────────── */
function analyzeVocabulary(text) {
  let suspicion = 0;

  const words = text.toLowerCase().match(/\b[a-z']+\b/g) || [];
  if (words.length < 10) return 50;

  const uniqueWords = new Set(words);
  const ttr = uniqueWords.size / words.length; // Type-Token Ratio

  // AI text often has moderate, consistent TTR
  if (ttr > 0.45 && ttr < 0.65) suspicion += 25; // AI sweet spot
  if (ttr < 0.3) suspicion += 15; // Very repetitive

  // Hapax legomena (words appearing only once)
  const freq = {};
  for (const w of words) freq[w] = (freq[w] || 0) + 1;
  const hapaxCount = Object.values(freq).filter(f => f === 1).length;
  const hapaxRatio = hapaxCount / uniqueWords.size;

  // AI text has fewer hapax legomena than human text
  if (hapaxRatio < 0.4) suspicion += 20;
  if (hapaxRatio < 0.3) suspicion += 15;

  // Average word length (AI uses slightly longer, more "sophisticated" words)
  const avgWordLen = words.reduce((a, w) => a + w.length, 0) / words.length;
  if (avgWordLen > 5.2) suspicion += 15;
  if (avgWordLen > 4.5 && avgWordLen < 5.5) suspicion += 8;

  return Math.min(100, suspicion);
}

/* ───────────────────────────────────────────────────────────
   VECTOR 3 – PERPLEXITY PROXY
   ─────────────────────────────────────────────────────────── */
function analyzePerplexity(text) {
  let suspicion = 0;

  // Character-level bigram predictability as a perplexity proxy
  const chars = text.toLowerCase().replace(/[^a-z ]/g, '');
  if (chars.length < 50) return 50;

  // Build character bigram model
  const bigramCounts = {};
  const unigramCounts = {};

  for (let i = 0; i < chars.length - 1; i++) {
    const uni = chars[i];
    const bi = chars.substring(i, i + 2);
    unigramCounts[uni] = (unigramCounts[uni] || 0) + 1;
    bigramCounts[bi] = (bigramCounts[bi] || 0) + 1;
  }

  // Calculate average predictability
  let totalLogProb = 0;
  let count = 0;
  for (let i = 0; i < chars.length - 1; i++) {
    const uni = chars[i];
    const bi = chars.substring(i, i + 2);
    if (unigramCounts[uni] > 0 && bigramCounts[bi] > 0) {
      const prob = bigramCounts[bi] / unigramCounts[uni];
      totalLogProb += Math.log2(prob);
      count++;
    }
  }

  const avgLogProb = count > 0 ? totalLogProb / count : -5;

  // MORE predictable (higher avg log prob) = more likely AI
  // AI text is more predictable than human text
  if (avgLogProb > -1.5) suspicion += 40; // Very predictable
  if (avgLogProb > -2.0) suspicion += 20;
  if (avgLogProb > -2.5) suspicion += 10;

  return Math.min(100, suspicion);
}

/* ───────────────────────────────────────────────────────────
   VECTOR 4 – REPETITION PATTERNS
   ─────────────────────────────────────────────────────────── */
function analyzeRepetition(text) {
  let suspicion = 0;

  const words = text.toLowerCase().match(/\b[a-z']+\b/g) || [];
  if (words.length < 20) return 50;

  // Check trigram repetition
  const trigrams = {};
  for (let i = 0; i < words.length - 2; i++) {
    const tri = `${words[i]} ${words[i + 1]} ${words[i + 2]}`;
    trigrams[tri] = (trigrams[tri] || 0) + 1;
  }

  const repeatedTrigrams = Object.values(trigrams).filter(c => c > 1).length;
  const trigramRepRate = repeatedTrigrams / Object.keys(trigrams).length;

  // AI text has more repeated trigrams
  if (trigramRepRate > 0.15) suspicion += 30;
  if (trigramRepRate > 0.08) suspicion += 15;

  // Check for common AI transition phrases
  const aiPhrases = [
    'it is important to note', 'it\'s worth noting',
    'in conclusion', 'furthermore',
    'additionally', 'moreover',
    'it is essential', 'it should be noted',
    'in today\'s world', 'in the realm of',
    'delve into', 'tapestry',
    'plays a crucial role', 'it is worth mentioning',
    'on the other hand', 'having said that',
    'let\'s explore', 'without a doubt',
    'stands as a testament', 'at its core',
    'serves as a', 'navigating the',
    'landscape of', 'multifaceted',
  ];

  const lowerText = text.toLowerCase();
  let phraseMatches = 0;
  for (const phrase of aiPhrases) {
    const regex = new RegExp(phrase.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi');
    const matches = lowerText.match(regex);
    if (matches) phraseMatches += matches.length;
  }

  if (phraseMatches >= 5) suspicion += 35;
  if (phraseMatches >= 3) suspicion += 20;
  if (phraseMatches >= 1) suspicion += 10;

  return Math.min(100, suspicion);
}

/* ───────────────────────────────────────────────────────────
   VECTOR 5 – STRUCTURAL UNIFORMITY
   ─────────────────────────────────────────────────────────── */
function analyzeStructure(text) {
  let suspicion = 0;

  const paragraphs = text.split(/\n\s*\n/).filter(p => p.trim().length > 0);
  if (paragraphs.length < 2) return 50;

  // Paragraph length uniformity
  const paraLengths = paragraphs.map(p => p.trim().split(/\s+/).length);
  const meanPara = paraLengths.reduce((a, b) => a + b, 0) / paraLengths.length;
  const stdPara = Math.sqrt(paraLengths.reduce((a, b) => a + (b - meanPara) ** 2, 0) / paraLengths.length);
  const cvPara = meanPara > 0 ? stdPara / meanPara : 0;

  // AI paragraphs are more uniform in length
  if (cvPara < 0.2) suspicion += 35;
  if (cvPara < 0.35) suspicion += 15;

  // Check for numbered/bulleted list patterns (AI loves lists)
  const listPatterns = text.match(/^\s*(\d+\.|[-•*])\s/gm) || [];
  const listRatio = listPatterns.length / Math.max(1, text.split('\n').length);
  if (listRatio > 0.3) suspicion += 15;

  // Check for header-like patterns
  const headerPatterns = text.match(/^#{1,3}\s|^\*\*[A-Z]/gm) || [];
  if (headerPatterns.length > 3) suspicion += 10;

  return Math.min(100, suspicion);
}

/* ───────────────────────────────────────────────────────────
   VECTOR 6 – LINGUISTIC MARKERS
   ─────────────────────────────────────────────────────────── */
function analyzeLinguisticMarkers(text) {
  let suspicion = 0;

  const words = text.toLowerCase().match(/\b[a-z']+\b/g) || [];
  if (words.length < 20) return 50;

  // Hedging language (AI hedges more than humans)
  const hedgeWords = ['generally', 'typically', 'often', 'usually', 'tend', 'tends',
    'might', 'may', 'could', 'perhaps', 'potentially', 'possibly',
    'somewhat', 'relatively', 'approximately', 'arguably'];
  const hedgeCount = words.filter(w => hedgeWords.includes(w)).length;
  const hedgeRate = hedgeCount / words.length;

  if (hedgeRate > 0.03) suspicion += 30;
  if (hedgeRate > 0.02) suspicion += 15;

  // Contraction analysis (humans use more contractions)
  const contractions = text.match(/\b\w+'(t|s|re|ve|d|ll|m)\b/gi) || [];
  const contractionRate = contractions.length / words.length;

  // LOW contraction rate = more AI-like
  if (contractionRate < 0.005 && words.length > 100) suspicion += 25;
  if (contractionRate < 0.01 && words.length > 100) suspicion += 12;

  // First person usage (AI tends to use third person more)
  const firstPerson = words.filter(w => ['i', 'me', 'my', 'mine', 'myself'].includes(w)).length;
  const firstPersonRate = firstPerson / words.length;
  if (firstPersonRate < 0.005 && words.length > 100) suspicion += 15;

  // Sentence starters analysis (AI starts with common patterns)
  const sentences = text.split(/[.!?]+/).filter(s => s.trim().length > 0);
  const starters = sentences.map(s => {
    const words = s.trim().split(/\s+/);
    return words.slice(0, 2).join(' ').toLowerCase();
  });

  const aiStarters = ['this is', 'it is', 'there are', 'there is', 'the ', 'in the', 'one of',
    'when it', 'as a', 'by the', 'with the', 'for the'];
  const aiStarterCount = starters.filter(s => aiStarters.some(as => s.startsWith(as))).length;
  const aiStarterRate = aiStarterCount / Math.max(1, starters.length);

  if (aiStarterRate > 0.4) suspicion += 20;
  if (aiStarterRate > 0.25) suspicion += 10;

  return Math.min(100, suspicion);
}

/* ───────────────────────────────────────────────────────────
   TEXT CLASSIFICATION
   ─────────────────────────────────────────────────────────── */
function classifyText(scores, text) {
  const weights = {
    burstiness: 2.5,
    vocabularyDiversity: 2.0,
    perplexityProxy: 2.2,
    repetitionPatterns: 2.5,
    structuralUniformity: 1.6,
    linguisticMarkers: 2.0,
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
  if (highVectors >= 3) rawScore += 10;
  if (highVectors >= 5) rawScore += 12;

  // Short text penalty (less reliable)
  const wordCount = text.split(/\s+/).length;
  if (wordCount < 50) rawScore = rawScore * 0.7 + 50 * 0.3;

  rawScore = Math.min(100, Math.max(0, rawScore));

  const sigmoid = (x) => 1 / (1 + Math.exp(-0.12 * (x - 40)));
  const aiProb = sigmoid(rawScore) * 100;

  const isAI = aiProb >= 50;
  const rawConf = isAI ? aiProb : 100 - aiProb;
  const confidence = Math.min(90, Math.max(51, Math.round(rawConf)));

  return { isAI, confidence, rawScore: Math.round(rawScore) };
}

/* ───────────────────────────────────────────────────────────
   EXPLANATION GENERATOR
   ─────────────────────────────────────────────────────────── */
function generateTextExplanation(result, scores) {
  const labels = {
    burstiness: 'unusually uniform sentence length patterns',
    vocabularyDiversity: 'formulaic vocabulary distribution',
    perplexityProxy: 'highly predictable character sequences',
    repetitionPatterns: 'recurring AI-typical phrase patterns',
    structuralUniformity: 'mechanically consistent paragraph structure',
    linguisticMarkers: 'excessive hedging and formal language patterns',
  };

  const top3 = Object.entries(scores)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 3)
    .map(([k]) => labels[k] ?? k);

  if (result.isAI) {
    return `This text exhibits AI-generation signatures with ${result.confidence}% confidence. ` +
      `Key linguistic evidence: ${top3.join(', ')}. ` +
      `These patterns are characteristic of large language models (GPT, Claude, Gemini, LLaMA) ` +
      `which produce text with distinct statistical fingerprints in burstiness, vocabulary, and structure.`;
  } else {
    return `This text appears to be human-written with ${result.confidence}% confidence. ` +
      `The natural variation in sentence structure, vocabulary choices, and grammatical patterns ` +
      `are consistent with authentic human writing. The text shows organic burstiness and unpredictability.`;
  }
}

module.exports = { analyze };
