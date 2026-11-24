'use strict';

// ============================================================
// AI Phishing Email Investigator - Backend Server
// IBM SkillsBuild Capstone Project
// ============================================================

const express = require('express');
const path = require('path');
const fs = require('fs');
const { GoogleGenAI } = require('@google/genai');

// Load environment variables from .env file
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// ============================================================
// Middleware
// ============================================================

// Parse JSON bodies — limit to 50kb to prevent abuse
app.use(express.json({ limit: '50kb' }));

// Parse URL-encoded bodies
app.use(express.urlencoded({ extended: true, limit: '50kb' }));

// Basic security headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  next();
});

// Serve static frontend files only from the public directory
app.use(express.static(path.join(__dirname, 'public')));

// ============================================================
// Input Validation Helper
// ============================================================

/**
 * Validate and sanitize investigation request fields.
 * Returns an error message string if invalid, or null if valid.
 */
function validateInvestigationInput(body) {
  const { senderName, senderEmail, subject, emailBody } = body;

  if (!senderName || typeof senderName !== 'string' || senderName.trim().length === 0) {
    return 'Sender name is required.';
  }
  if (!senderEmail || typeof senderEmail !== 'string' || senderEmail.trim().length === 0) {
    return 'Sender email address is required.';
  }
  if (!subject || typeof subject !== 'string' || subject.trim().length === 0) {
    return 'Email subject is required.';
  }
  if (!emailBody || typeof emailBody !== 'string' || emailBody.trim().length === 0) {
    return 'Email body is required.';
  }

  // Length limits to prevent excessively large requests
  if (senderName.trim().length > 200) return 'Sender name is too long (max 200 characters).';
  if (senderEmail.trim().length > 320) return 'Sender email is too long (max 320 characters).';
  if (subject.trim().length > 500) return 'Subject is too long (max 500 characters).';
  if (emailBody.trim().length > 10000) return 'Email body is too long (max 10,000 characters).';

  // Optional fields — validate if present
  const optionalStringFields = ['url', 'rawHeaders', 'spfResult', 'dkimResult', 'dmarcResult'];
  for (const field of optionalStringFields) {
    if (body[field] !== undefined && body[field] !== null && body[field] !== '') {
      if (typeof body[field] !== 'string') return `Field "${field}" must be a string.`;
      if (body[field].length > 5000) return `Field "${field}" is too long (max 5,000 characters).`;
    }
  }

  // Language field — must be one of the supported values if provided
  if (body.language !== undefined && body.language !== null && body.language !== '') {
    if (!['id', 'en'].includes(body.language)) return 'Invalid language value. Supported values: id, en.';
  }

  return null;
}

/**
 * Sanitize a string by trimming and removing null bytes.
 */
function sanitizeString(str) {
  if (!str || typeof str !== 'string') return '';
  return str.trim().replace(/\0/g, '');
}

// ============================================================
// System Prompt Loader
// ============================================================

/**
 * Load the system prompt from prompts/system-prompt.md.
 * Returns the prompt text, or throws an error if the file is missing.
 */
function loadSystemPrompt() {
  const promptPath = path.join(__dirname, 'prompts', 'system-prompt.md');
  if (!fs.existsSync(promptPath)) {
    throw new Error('System prompt file not found at prompts/system-prompt.md');
  }
  return fs.readFileSync(promptPath, 'utf8');
}

// ============================================================
// AI Analysis Request Builder
// ============================================================

/**
 * Build the user message for the AI based on submitted investigation data.
 * Includes a language instruction so the AI generates the report in the requested language.
 */
function buildUserMessage(data) {
  // Determine language instruction to prepend
  const lang = data.language === 'id' ? 'id' : 'en';
  const langInstruction = lang === 'id'
    ? 'IMPORTANT: Generate the ENTIRE investigation report in Bahasa Indonesia. Translate all section headings, explanations, findings, risk descriptions, recommendations, and summaries into Indonesian. Preserve technical terms such as SPF, DKIM, DMARC, URL, HTTP, HTTPS, phishing, spoofing, and SQL Injection in their original form where appropriate. Do NOT translate non-text enum values: riskLevel must be strictly LOW, MEDIUM, HIGH, or CRITICAL; confidenceLevel must be strictly LOW, MEDIUM, or HIGH; threatClassification must be strictly Potential Phishing, Suspicious Email, No Significant Phishing Indicators Identified, or Inconclusive.'
    : 'Generate the ENTIRE investigation report in English. Do NOT translate non-text enum values: riskLevel must be strictly LOW, MEDIUM, HIGH, or CRITICAL; confidenceLevel must be strictly LOW, MEDIUM, or HIGH; threatClassification must be strictly Potential Phishing, Suspicious Email, No Significant Phishing Indicators Identified, or Inconclusive.';

  const lines = [
    langInstruction,
    '',
    'Please investigate the following email and return a structured JSON investigation report.',
    '',
    `**Sender Name:** ${data.senderName}`,
    `**Sender Email:** ${data.senderEmail}`,
    `**Subject:** ${data.subject}`,
    '',
    '**Email Body:**',
    data.emailBody,
  ];

  lines.push('', `**URL:** ${data.url && data.url.trim() ? data.url.trim() : 'Not provided by user'}`);
  lines.push('', `**Raw Email Headers:** ${data.rawHeaders && data.rawHeaders.trim() ? data.rawHeaders.trim() : 'Not provided by user'}`);

  const authResults = [
    `SPF: ${data.spfResult && data.spfResult.trim() ? data.spfResult.trim() : 'Not provided by user'}`,
    `DKIM: ${data.dkimResult && data.dkimResult.trim() ? data.dkimResult.trim() : 'Not provided by user'}`,
    `DMARC: ${data.dmarcResult && data.dmarcResult.trim() ? data.dmarcResult.trim() : 'Not provided by user'}`
  ];

  lines.push('', '**Authentication Results:**', ...authResults.map(r => `- ${r}`));

  lines.push(
    '',
    'Analyze this email completely. Return only a valid JSON object matching the required output format.',
    'Do not include markdown, code fences, or any text outside the JSON object.'
  );

  return lines.join('\n');
}

// ============================================================
// Google Gemini API Call
// ============================================================

/**
 * Call the Google Gemini API with the investigation data.
 * Uses @google/genai SDK with GoogleGenAI client.
 * Returns the parsed JSON investigation result.
 */
async function callGeminiJson(systemPrompt, userMessage) {
  const apiKey = process.env.GEMINI_API_KEY;
  const model  = process.env.GEMINI_MODEL || 'gemini-3.5-flash';

  if (!apiKey || apiKey.trim() === '') {
    throw { type: 'CONFIG_ERROR', message: 'API key is not configured. Please set GEMINI_API_KEY in your .env file.' };
  }

  // Initialise the Gemini client
  const ai = new GoogleGenAI({ apiKey });

  // 60-second timeout via AbortController
  const controller = new AbortController();
  const timeoutId  = setTimeout(() => controller.abort(), 60000);

  try {
    const response = await ai.models.generateContent({
      model,
      contents: userMessage,
      config: {
        systemInstruction: systemPrompt,
        temperature:      0.2,
        maxOutputTokens:  4000,
        // Request JSON output directly — Gemini will return valid JSON
        responseMimeType: 'application/json',
        abortSignal: controller.signal,
      },
    });

    clearTimeout(timeoutId);

    const responseText = response.text;
    if (!responseText || responseText.trim() === '') {
      throw { type: 'INVALID_RESPONSE', message: 'Gemini returned an empty response. Please try again.' };
    }

    let cleanContent = responseText.trim();
    if (cleanContent.startsWith('```')) {
      cleanContent = cleanContent.replace(/^```[a-z]*\n?/, '').replace(/\n?```$/, '').trim();
    }

    try {
      return JSON.parse(cleanContent);
    } catch {
      throw { type: 'PARSE_ERROR', message: 'Gemini returned a response that could not be parsed as JSON. Please try again.' };
    }

  } catch (err) {
    clearTimeout(timeoutId);

        console.error('Gemini API Diagnostic:', {
      name: err?.name,
      status: err?.status,
      httpStatus: err?.httpStatus,
      message: err?.message,
      cause: err?.cause?.message,
      errorDetails: err?.errorDetails
    });

    // AbortController fires with DOMException name 'AbortError'
    if (err.name === 'AbortError') {
      throw { type: 'TIMEOUT', message: 'AI analysis request timed out after 60 seconds. Please try again.' };
    }

    // Google GenAI SDK surfaces HTTP errors as ApiError instances
    const msg    = err?.message || '';
    const status = err?.status  ?? err?.httpStatus ?? 0;

    if (status === 401 || msg.includes('API_KEY_INVALID') || msg.includes('401')) {
      throw { type: 'AUTH_ERROR', message: 'Gemini API authentication failed. Check your GEMINI_API_KEY.' };
    }
    if (status === 429 || msg.includes('RESOURCE_EXHAUSTED') || msg.includes('429')) {
      throw { type: 'RATE_LIMIT', message: 'Gemini API rate limit exceeded. Please wait and try again.' };
    }
    if (status === 503 || status === 502 || msg.includes('503') || msg.includes('502')) {
      throw { type: 'SERVICE_ERROR', message: 'Gemini service is temporarily unavailable. Please try again later.' };
    }
    if (msg.includes('fetch') || msg.includes('ENOTFOUND') || msg.includes('ECONNREFUSED')) {
      throw { type: 'NETWORK_ERROR', message: `Network error connecting to Gemini API: ${msg}` };
    }

    // Re-throw already-typed errors (e.g., from nested calls)
    if (err.type) throw err;

    throw { type: 'API_ERROR', message: `Gemini API error: ${msg.substring(0, 200)}` };
  }

}

/**
 * Analysis-specific validation remains separate from the generic Gemini JSON call.
 */
async function callAIAnalysis(systemPrompt, userMessage) {
  const parsedResult = await callGeminiJson(systemPrompt, userMessage);

  // Basic structure validation — ensure all required report fields are present
  const requiredFields = [
    'executiveSummary', 'emailInfo', 'senderAnalysis', 'socialEngineeringAnalysis',
    'urlAnalysis', 'headerAnalysis', 'suspiciousIndicators', 'evidenceAnalysis',
    'threatClassification', 'riskLevel', 'confidenceLevel', 'riskExplanation',
    'confidenceExplanation', 'recommendedActions', 'investigationLimitations'
  ];

  for (const field of requiredFields) {
    if (!(field in parsedResult)) {
      throw { type: 'INVALID_RESPONSE', message: `Gemini response is missing required field: "${field}". Please try again.` };
    }
  }

  // Validate riskLevel enum
  const validRiskLevels = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
  const riskStr = String(parsedResult.riskLevel || '').trim().toUpperCase();
  if (!validRiskLevels.includes(riskStr)) {
    throw { type: 'INVALID_RESPONSE', message: `Invalid riskLevel value in Gemini response: "${parsedResult.riskLevel}". Expected: ${validRiskLevels.join(', ')}.` };
  }
  parsedResult.riskLevel = riskStr;

  // Validate confidenceLevel enum
  const validConfidenceLevels = ['LOW', 'MEDIUM', 'HIGH'];
  const confStr = String(parsedResult.confidenceLevel || '').trim().toUpperCase();
  if (!validConfidenceLevels.includes(confStr)) {
    throw { type: 'INVALID_RESPONSE', message: `Invalid confidenceLevel value in Gemini response: "${parsedResult.confidenceLevel}". Expected: ${validConfidenceLevels.join(', ')}.` };
  }
  parsedResult.confidenceLevel = confStr;

  // Validate threatClassification enum
  const validThreatClassifications = [
    'Potential Phishing',
    'Suspicious Email',
    'No Significant Phishing Indicators Identified',
    'Inconclusive'
  ];
  const threatStr = String(parsedResult.threatClassification || '').trim();
  const matchedThreat = validThreatClassifications.find(t => t.toLowerCase() === threatStr.toLowerCase());
  if (!matchedThreat) {
    throw { type: 'INVALID_RESPONSE', message: `Invalid threatClassification value in Gemini response: "${parsedResult.threatClassification}". Expected one of: ${validThreatClassifications.join(', ')}.` };
  }
  parsedResult.threatClassification = matchedThreat;

  // Helper for strictly validating plain objects (non-null, non-array object)
  const isPlainObject = (val) => typeof val === 'object' && val !== null && !Array.isArray(val);

  // Validate string fields (must be typeof 'string', rejecting null, arrays, objects)
  const requiredStringFields = [
    'executiveSummary',
    'senderAnalysis',
    'socialEngineeringAnalysis',
    'urlAnalysis',
    'headerAnalysis',
    'riskExplanation',
    'confidenceExplanation'
  ];

  for (const field of requiredStringFields) {
    if (typeof parsedResult[field] !== 'string') {
      throw { type: 'INVALID_RESPONSE', message: `Field "${field}" must be a string in Gemini response.` };
    }
  }

  // Validate emailInfo object and its 9 required string properties
  if (!isPlainObject(parsedResult.emailInfo)) {
    throw { type: 'INVALID_RESPONSE', message: 'Field "emailInfo" must be an object (not an array) in Gemini response.' };
  }

  const requiredEmailInfoProps = [
    'senderName',
    'senderEmail',
    'senderDomain',
    'subject',
    'urlsProvided',
    'headersProvided',
    'spf',
    'dkim',
    'dmarc'
  ];

  for (const prop of requiredEmailInfoProps) {
    if (typeof parsedResult.emailInfo[prop] !== 'string') {
      throw { type: 'INVALID_RESPONSE', message: `Property "emailInfo.${prop}" must be a string in Gemini response.` };
    }
  }

  // Validate suspiciousIndicators array of objects
  if (!Array.isArray(parsedResult.suspiciousIndicators)) {
    throw { type: 'INVALID_RESPONSE', message: 'Field "suspiciousIndicators" must be an array in Gemini response.' };
  }

  const validIndicatorSeverities = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
  for (let i = 0; i < parsedResult.suspiciousIndicators.length; i++) {
    const item = parsedResult.suspiciousIndicators[i];
    if (!isPlainObject(item)) {
      throw { type: 'INVALID_RESPONSE', message: `Item at index ${i} in "suspiciousIndicators" must be an object in Gemini response.` };
    }
    if (typeof item.indicator !== 'string') {
      throw { type: 'INVALID_RESPONSE', message: `Property "indicator" at index ${i} in "suspiciousIndicators" must be a string.` };
    }
    if (typeof item.category !== 'string') {
      throw { type: 'INVALID_RESPONSE', message: `Property "category" at index ${i} in "suspiciousIndicators" must be a string.` };
    }
    if (typeof item.assessment !== 'string') {
      throw { type: 'INVALID_RESPONSE', message: `Property "assessment" at index ${i} in "suspiciousIndicators" must be a string.` };
    }
    const itemSeverity = String(item.severity || '').trim().toUpperCase();
    if (!validIndicatorSeverities.includes(itemSeverity)) {
      throw { type: 'INVALID_RESPONSE', message: `Property "severity" at index ${i} in "suspiciousIndicators" must be one of: ${validIndicatorSeverities.join(', ')}.` };
    }
    item.severity = itemSeverity;
  }

  // Validate evidenceAnalysis object and its 3 array of strings properties
  if (!isPlainObject(parsedResult.evidenceAnalysis)) {
    throw { type: 'INVALID_RESPONSE', message: 'Field "evidenceAnalysis" must be an object (not an array) in Gemini response.' };
  }

  const evidenceSubFields = ['confirmedObservations', 'suspiciousIndicators', 'unverifiedAssumptions'];
  for (const sub of evidenceSubFields) {
    if (!Array.isArray(parsedResult.evidenceAnalysis[sub])) {
      throw { type: 'INVALID_RESPONSE', message: `Field "evidenceAnalysis.${sub}" must be an array in Gemini response.` };
    }
    if (!parsedResult.evidenceAnalysis[sub].every(item => typeof item === 'string')) {
      throw { type: 'INVALID_RESPONSE', message: `Every item in "evidenceAnalysis.${sub}" must be a string in Gemini response.` };
    }
  }

  // Validate recommendedActions and investigationLimitations (array of strings)
  if (!Array.isArray(parsedResult.recommendedActions) || !parsedResult.recommendedActions.every(item => typeof item === 'string')) {
    throw { type: 'INVALID_RESPONSE', message: 'Field "recommendedActions" must be an array of strings in Gemini response.' };
  }
  if (!Array.isArray(parsedResult.investigationLimitations) || !parsedResult.investigationLimitations.every(item => typeof item === 'string')) {
    throw { type: 'INVALID_RESPONSE', message: 'Field "investigationLimitations" must be an array of strings in Gemini response.' };
  }

  return parsedResult;
}

function validateTranslatedResult(source, translated) {
  const isObject = value => value && typeof value === 'object' && !Array.isArray(value);
  if (!isObject(translated)) {
    throw { type: 'INVALID_RESPONSE', message: 'Gemini translation did not return a JSON object.' };
  }

  const compareShape = (expected, actual, path = 'result') => {
    if (Array.isArray(expected)) {
      if (!Array.isArray(actual) || expected.length !== actual.length) {
        throw { type: 'INVALID_RESPONSE', message: `Translation changed array structure at ${path}.` };
      }
      expected.forEach((item, index) => compareShape(item, actual[index], `${path}[${index}]`));
      return;
    }
    if (isObject(expected)) {
      if (!isObject(actual)) throw { type: 'INVALID_RESPONSE', message: `Translation changed object structure at ${path}.` };
      const expectedKeys = Object.keys(expected).sort();
      const actualKeys = Object.keys(actual).sort();
      if (expectedKeys.join('|') !== actualKeys.join('|')) {
        throw { type: 'INVALID_RESPONSE', message: `Translation changed property structure at ${path}.` };
      }
      expectedKeys.forEach(key => compareShape(expected[key], actual[key], `${path}.${key}`));
    }
  };

  compareShape(source, translated);
  if (!['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(translated.riskLevel)) {
    throw { type: 'INVALID_RESPONSE', message: 'Translation changed riskLevel.' };
  }
  if (!['LOW', 'MEDIUM', 'HIGH'].includes(translated.confidenceLevel)) {
    throw { type: 'INVALID_RESPONSE', message: 'Translation changed confidenceLevel.' };
  }
  if (translated.threatClassification !== source.threatClassification) {
    throw { type: 'INVALID_RESPONSE', message: 'Translation changed threatClassification.' };
  }
  const preservedPaths = ['emailInfo.senderEmail', 'emailInfo.senderDomain'];
  for (const fieldPath of preservedPaths) {
    const sourceValue = fieldPath.split('.').reduce((value, key) => value?.[key], source);
    const translatedValue = fieldPath.split('.').reduce((value, key) => value?.[key], translated);
    if (sourceValue !== translatedValue) {
      throw { type: 'INVALID_RESPONSE', message: `Translation changed technical value at ${fieldPath}.` };
    }
  }
  const sourceUrl = source.emailInfo?.urlsProvided || '';
  if (sourceUrl.includes('://') && translated.emailInfo?.urlsProvided !== sourceUrl) {
    throw { type: 'INVALID_RESPONSE', message: 'Translation changed the provided URL.' };
  }
  return translated;
}

async function callAITranslation(systemPrompt, userMessage, sourceResult) {
  const translated = await callGeminiJson(systemPrompt, userMessage);
  return validateTranslatedResult(sourceResult, translated);
}

// ============================================================
// API Routes
// ============================================================

/**
 * POST /api/analyze
 * Accepts email investigation data and returns AI analysis results.
 */
app.post('/api/analyze', async (req, res) => {
  // Validate input
  const validationError = validateInvestigationInput(req.body);
  if (validationError) {
    return res.status(400).json({ error: validationError, type: 'VALIDATION_ERROR' });
  }

  // Sanitize all inputs — include language with safe fallback
  const rawLang = sanitizeString(req.body.language);
  const data = {
    senderName:  sanitizeString(req.body.senderName),
    senderEmail: sanitizeString(req.body.senderEmail),
    subject:     sanitizeString(req.body.subject),
    emailBody:   sanitizeString(req.body.emailBody),
    url:         sanitizeString(req.body.url),
    rawHeaders:  sanitizeString(req.body.rawHeaders),
    spfResult:   sanitizeString(req.body.spfResult),
    dkimResult:  sanitizeString(req.body.dkimResult),
    dmarcResult: sanitizeString(req.body.dmarcResult),
    language:    ['id', 'en'].includes(rawLang) ? rawLang : 'en',
  };

  // Load system prompt
  let systemPrompt;
  try {
    systemPrompt = loadSystemPrompt();
  } catch (err) {
    console.error('System prompt load error:', err.message);
    return res.status(500).json({
      error: 'Server configuration error: system prompt file is missing.',
      type: 'CONFIG_ERROR'
    });
  }

  // Build user message
  const userMessage = buildUserMessage(data);

  // Call AI
  try {
    const result = await callAIAnalysis(systemPrompt, userMessage);
    return res.json({ success: true, result });
  } catch (err) {
    console.error(`AI analysis error [${err.type || 'UNKNOWN'}]:`, err.message);

    const statusMap = {
      CONFIG_ERROR: 503,
      AUTH_ERROR: 401,
      RATE_LIMIT: 429,
      TIMEOUT: 504,
      SERVICE_ERROR: 503,
      NETWORK_ERROR: 502,
      PARSE_ERROR: 502,
      INVALID_RESPONSE: 502,
      API_ERROR: 502,
    };

    const status = statusMap[err.type] || 500;
    return res.status(status).json({
      error: err.message || 'An unexpected error occurred during analysis.',
      type: err.type || 'SERVER_ERROR'
    });
  }
});

/**
 * POST /api/translate
 * Translates an existing investigation result JSON into a different language.
 * Does not re-run phishing analysis — only translates text fields.
 */
app.post('/api/translate', async (req, res) => {
  const { result, language } = req.body;

  // Validate language
  if (!language || !['id', 'en'].includes(language)) {
    return res.status(400).json({ error: 'Invalid or missing language. Supported values: id, en.', type: 'VALIDATION_ERROR' });
  }

  // Validate result presence
  if (!result || typeof result !== 'object') {
    return res.status(400).json({ error: 'Missing or invalid result object.', type: 'VALIDATION_ERROR' });
  }

  // Translation has its own system prompt so the investigation workflow and
  // analysis instructions cannot conflict with this endpoint.
  const systemPrompt = [
    'You are a precise JSON localization assistant for an email security report.',
    `Translate the report's human-readable prose into ${language === 'id' ? 'Bahasa Indonesia' : 'English'}.`,
    'Return ONLY one valid JSON object with exactly the same structure, property names, arrays, and object nesting.',
    'Translate every narrative string, including nested strings in emailInfo, suspiciousIndicators, evidenceAnalysis,',
    'riskExplanation, confidenceExplanation, recommendedActions, and investigationLimitations.',
    'Preserve these values exactly: riskLevel (LOW, MEDIUM, HIGH, CRITICAL), confidenceLevel (LOW, MEDIUM, HIGH),',
    'threatClassification enum values (Potential Phishing, Suspicious Email, No Significant Phishing Indicators Identified, Inconclusive),',
    'email addresses, sender domains, URLs, IP addresses, SPF/DKIM/DMARC values, HTTP/HTTPS, and technical identifiers.',
    'Do not add, remove, or reorder fields. Do not include markdown or explanatory text outside the JSON.'
  ].join(' ');
  const langInstruction = language === 'id'
    ? 'Translate the report into Bahasa Indonesia.'
    : 'Translate the report into English.';

  const userMessage = `${langInstruction}\n\nJSON to translate:\n${JSON.stringify(result)}`;

  try {
    const translated = await callAITranslation(systemPrompt, userMessage, result);
    return res.json({ success: true, result: translated });
  } catch (err) {
    console.error(`Translation error [${err.type || 'UNKNOWN'}]:`, err.message);

    const statusMap = {
      CONFIG_ERROR: 503, AUTH_ERROR: 401, RATE_LIMIT: 429,
      TIMEOUT: 504, SERVICE_ERROR: 503, NETWORK_ERROR: 502,
      PARSE_ERROR: 502, INVALID_RESPONSE: 502, API_ERROR: 502,
    };

    const status = statusMap[err.type] || 500;
    return res.status(status).json({
      error: err.message || 'An unexpected error occurred during translation.',
      type: err.type || 'SERVER_ERROR'
    });
  }
});

/**
 * GET /api/health
 * Health check endpoint — confirms server and Gemini API configuration status.
 */
app.get('/api/health', (req, res) => {
  const apiKey     = process.env.GEMINI_API_KEY;
  const configured = !!(apiKey && apiKey.trim() !== '');

  res.json({
    status: 'ok',
    apiConfigured: configured,
    provider: 'Google Gemini',
    model: process.env.GEMINI_MODEL || 'gemini-3.5-flash',
    timestamp: new Date().toISOString()
  });
});

// ============================================================
// 404 Handler — Return 404 for all unhandled routes
// ============================================================
app.use((req, res) => {
  res.status(404).send('Not Found');
});

// ============================================================
// Start Server
// ============================================================
app.listen(PORT, () => {
  const apiKey     = process.env.GEMINI_API_KEY;
  const configured = !!(apiKey && apiKey.trim() !== '');

  console.log('============================================================');
  console.log('  AI Phishing Email Investigator');
  console.log('  IBM SkillsBuild Capstone Project');
  console.log('============================================================');
  console.log(`  Server running at: http://localhost:${PORT}`);
  console.log(`  Provider:          Google Gemini`);
  console.log(`  API configured:    ${configured ? 'YES ✓' : 'NO — set GEMINI_API_KEY in .env'}`);
  if (configured) {
    console.log(`  Model:             ${process.env.GEMINI_MODEL || 'gemini-3.5-flash'}`);
  }
  console.log('============================================================');
});
