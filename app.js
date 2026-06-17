/**
 * JWT Cipher — Core Cryptographic & Application Logic (v4.0)
 * Powered entirely by the Browser's native Web Crypto API.
 *
 * v4.0:
 *  - Theme toggle (dark/light) with localStorage persistence
 *  - Hash Generator tab (SHA-256/384/512 + HMAC + file hash)
 *  - Password Generator tab (configurable, entropy meter, batch)
 *  - QR Code generator (inline, no external dependencies)
 *  - JSON prettify/minify buttons
 *  - Quick claim inserters (+jti, +nbf, +aud, +iss, +sub)
 *  - Token size counter
 *  - Keyboard shortcuts (Ctrl+Enter = encode, Ctrl+Shift+C = copy)
 *  - Animated pill tab bar with sliding indicator
 *  - Enhanced color-coded toasts with progress bar
 *
 * v3.0:
 *  - RS256 (RSA-PKCS1-v1_5 / SHA-256) signing & verification
 *  - RSA-2048 key pair generation with PEM export
 *  - HMAC Key Strength Advisor (visual gauge + hints)
 *  - Token Validation Checklist (structure, expiry, signature, claims)
 *  - Universal Encoding Converter (Text ↔ Hex ↔ Base64 ↔ Base64URL)
 */

(() => {
  'use strict';

  // ==========================================================================
  // DOM Elements Selection
  // ==========================================================================
  const $ = id => document.getElementById(id);

  const els = {
    // Navigation
    navBar: $('nav-bar'),
    tabIndicator: $('tab-indicator'),
    tabBtnStandard: $('tab-btn-standard'),
    tabBtnEncrypted: $('tab-btn-encrypted'),
    tabBtnUtilities: $('tab-btn-utilities'),
    tabBtnConverter: $('tab-btn-converter'),
    tabBtnHash: $('tab-btn-hash'),
    tabBtnPassword: $('tab-btn-password'),
    panelStandard: $('panel-standard'),
    panelEncrypted: $('panel-encrypted'),
    panelUtilities: $('panel-utilities'),
    panelConverter: $('panel-converter'),
    panelHash: $('panel-hash'),
    panelPassword: $('panel-password'),

    // Theme toggle
    btnThemeToggle: $('btn-theme-toggle'),

    // Standard JWT Panel
    jwtAlg: $('jwt-alg'),
    jwtHeader: $('jwt-header'),
    jwtPayload: $('jwt-payload'),
    jwtKey: $('jwt-key'),
    keyFormatText: $('key-format-text'),
    keyFormatHex: $('key-format-hex'),
    btnToggleKeyVisibility: $('btn-toggle-key-visibility'),
    headerStatus: $('header-status'),
    payloadStatus: $('payload-status'),
    jwtEncoded: $('jwt-encoded'),
    tokenStatus: $('token-status'),
    visHeader: $('vis-header'),
    visPayload: $('vis-payload'),
    visSignature: $('vis-signature'),
    btnCopyToken: $('btn-copy-token'),
    btnTamperToken: $('btn-tamper-token'),
    btnSendToEncryptor: $('btn-send-to-encryptor'),
    decodedHeaderView: $('decoded-header-view'),
    decodedPayloadView: $('decoded-payload-view'),

    // JSON prettify/minify
    btnPrettify: $('btn-prettify'),
    btnMinify: $('btn-minify'),

    // Token size & QR
    tokenSizeBadge: $('token-size-badge'),
    btnGenerateQr: $('btn-generate-qr'),
    qrSection: $('qr-section'),
    qrCanvas: $('qr-canvas'),

    // Time helpers & Templates
    claimsTemplate: $('claims-template'),
    btnTimeNow: $('btn-time-now'),
    btnTime1h: $('btn-time-1h'),
    btnTime1d: $('btn-time-1d'),
    btnTime7d: $('btn-time-7d'),
    ttlStatusBar: $('ttl-status-bar'),
    ttlText: $('ttl-text'),

    // HMAC key group & RSA key group (toggle)
    hmacKeyGroup: $('hmac-key-group'),
    rsaKeyGroup: $('rsa-key-group'),
    rsaPrivateKey: $('rsa-private-key'),
    rsaPublicKey: $('rsa-public-key'),
    btnGenerateRsa: $('btn-generate-rsa'),

    // Strength advisor
    strengthAdvisor: $('strength-advisor'),
    strengthValue: $('strength-value'),
    strengthFill: $('strength-fill'),
    strengthHints: $('strength-hints'),

    // Validation Checklist
    validationChecklist: $('validation-checklist'),
    checklistItems: $('checklist-items'),
    checklistScore: $('checklist-score'),

    // Encrypted GCM Panel
    encPlaintext: $('enc-plaintext'),
    encKey: $('enc-key'),
    encKeyFormatText: $('enc-key-format-text'),
    encKeyFormatHex: $('enc-key-format-hex'),
    btnToggleEncKeyVisibility: $('btn-toggle-enc-key-visibility'),
    encKeyDerive: $('enc-key-derive'),
    encCustomIv: $('enc-custom-iv'),
    btnEncrypt: $('btn-encrypt'),
    encCiphertext: $('enc-ciphertext'),
    btnCopyEncToken: $('btn-copy-enc-token'),

    decToken: $('dec-token'),
    decKey: $('dec-key'),
    decKeyFormatText: $('dec-key-format-text'),
    decKeyFormatHex: $('dec-key-format-hex'),
    btnToggleDecKeyVisibility: $('btn-toggle-dec-key-visibility'),
    decKeyDerive: $('dec-key-derive'),
    btnDecrypt: $('btn-decrypt'),
    decResultSection: $('dec-result-section'),
    decPlaintext: $('dec-plaintext'),
    decStatusBadge: $('dec-status-badge'),
    btnCopyDecPlaintext: $('btn-copy-dec-plaintext'),
    btnSendToDecoder: $('btn-send-to-decoder'),
    analysisIvHex: $('analysis-iv-hex'),
    analysisCipherHex: $('analysis-cipher-hex'),
    analysisCipherMeta: $('analysis-cipher-meta'),
    analysisTagHex: $('analysis-tag-hex'),

    // Utilities Panel
    genKeySize: $('gen-key-size'),
    genKeyFormat: $('gen-key-format'),
    btnGenerateRandomKey: $('btn-generate-random-key'),
    generatedOutputKey: $('generated-output-key'),
    btnCopyGenKey: $('btn-copy-gen-key'),
    btnGenerateRsaUtility: $('btn-generate-rsa-utility'),
    rsaGenPrivate: $('rsa-gen-private'),
    rsaGenPublic: $('rsa-gen-public'),
    btnCopyRsaPrivate: $('btn-copy-rsa-private'),
    btnCopyRsaPublic: $('btn-copy-rsa-public'),
    btnUseRsaKeys: $('btn-use-rsa-keys'),
    deriveInputText: $('derive-input-text'),
    derivedHexOutput: $('derived-hex-output'),
    derivedBase64Output: $('derived-base64-output'),
    btnCopyDerivedHex: $('btn-copy-derived-hex'),
    btnCopyDerivedBase64: $('btn-copy-derived-base64'),

    // Converter Panel
    convInput: $('conv-input'),
    convInputFormat: $('conv-input-format'),
    btnConvert: $('btn-convert'),
    convOutText: $('conv-out-text'),
    convOutHex: $('conv-out-hex'),
    convOutBase64: $('conv-out-base64'),
    convOutBase64url: $('conv-out-base64url'),
    btnCopyConvText: $('btn-copy-conv-text'),
    btnCopyConvHex: $('btn-copy-conv-hex'),
    btnCopyConvBase64: $('btn-copy-conv-base64'),
    btnCopyConvBase64url: $('btn-copy-conv-base64url'),

    // Hash Generator Panel
    hashModeText: $('hash-mode-text'),
    hashModeHmac: $('hash-mode-hmac'),
    hashModeFile: $('hash-mode-file'),
    hashTextGroup: $('hash-text-group'),
    hashHmacGroup: $('hash-hmac-group'),
    hashFileGroup: $('hash-file-group'),
    hashInput: $('hash-input'),
    hashHmacKey: $('hash-hmac-key'),
    hashFileDrop: $('hash-file-drop'),
    hashFileInput: $('hash-file-input'),
    hashFileInfo: $('hash-file-info'),
    btnHashCompute: $('btn-hash-compute'),
    hashSha256: $('hash-sha256'),
    hashSha384: $('hash-sha384'),
    hashSha512: $('hash-sha512'),
    btnCopySha256: $('btn-copy-sha256'),
    btnCopySha384: $('btn-copy-sha384'),
    btnCopySha512: $('btn-copy-sha512'),

    // Password Generator Panel
    pwLength: $('pw-length'),
    pwLengthValue: $('pw-length-value'),
    pwUpper: $('pw-upper'),
    pwLower: $('pw-lower'),
    pwDigits: $('pw-digits'),
    pwSymbols: $('pw-symbols'),
    pwBatchCount: $('pw-batch-count'),
    btnGeneratePasswords: $('btn-generate-passwords'),
    entropyBits: $('entropy-bits'),
    entropyFill: $('entropy-fill'),
    pwOutputList: $('pw-output-list'),

    // Global
    toastContainer: $('toast-container')
  };

  // State
  let isEditingEncoded = false;
  let currentHashMode = 'text';
  let selectedHashFile = null;

  // Templates definitions
  const TEMPLATES = {
    session: {
      sub: "1234567890",
      name: "Mark Lester",
      role: "User",
      permissions: ["read:reports", "write:comments"],
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600 // 1 hour
    },
    oauth: {
      iss: "https://auth.telexph.com/",
      sub: "usr_94fbc2aaa6d58",
      aud: ["https://api.telexph.com/v1", "https://txhive.telexph.com/"],
      client_id: "client_oauth_2026",
      scope: "openid profile email api:read api:write",
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 86400 // 24 hours
    },
    micro: {
      iss: "https://wanderwaveph.com",
      sub: "service_account_sync",
      aud: "https://smoobu.com/api/v2",
      scope: "sync:properties sync:bookings",
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 604800 // 7 days
    },
    clear: {}
  };

  const defaultHeader = {
    alg: "HS256",
    typ: "JWT"
  };

  // ==========================================================================
  // Cryptographic Helper Functions
  // ==========================================================================

  function bufToHex(buffer) {
    const bytes = new Uint8Array(buffer);
    return Array.from(bytes)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  function hexToBuf(hex) {
    const cleaned = hex.replace(/\s+/g, '');
    if (cleaned.length % 2 !== 0) throw new Error('Invalid hex string length');
    const bytes = new Uint8Array(cleaned.length / 2);
    for (let i = 0; i < cleaned.length; i += 2) {
      bytes[i / 2] = parseInt(cleaned.substring(i, i + 2), 16);
    }
    return bytes;
  }

  function base64urlEncode(arrayBuffer) {
    const bytes = new Uint8Array(arrayBuffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    const base64 = btoa(binary);
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }

  function base64urlDecode(str) {
    let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4) {
      base64 += '=';
    }
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  async function sha256(data) {
    const encoder = new TextEncoder();
    const bytes = typeof data === 'string' ? encoder.encode(data) : data;
    const hashBuffer = await crypto.subtle.digest('SHA-256', bytes);
    return new Uint8Array(hashBuffer);
  }

  async function prepareKeyBytes(rawKey, format, shouldDerive) {
    let keyBytes;
    if (format === 'hex') {
      try {
        keyBytes = hexToBuf(rawKey);
      } catch (e) {
        throw new Error('Key is not a valid hex string');
      }
    } else {
      keyBytes = new TextEncoder().encode(rawKey);
    }

    if (shouldDerive) {
      keyBytes = await sha256(keyBytes);
    }
    return keyBytes;
  }

  // ==========================================================================
  // RSA PEM Helpers
  // ==========================================================================

  function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  function base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  function exportPemPrivate(keyBuffer) {
    const b64 = arrayBufferToBase64(keyBuffer);
    const lines = b64.match(/.{1,64}/g) || [];
    return `-----BEGIN PRIVATE KEY-----\n${lines.join('\n')}\n-----END PRIVATE KEY-----`;
  }

  function exportPemPublic(keyBuffer) {
    const b64 = arrayBufferToBase64(keyBuffer);
    const lines = b64.match(/.{1,64}/g) || [];
    return `-----BEGIN PUBLIC KEY-----\n${lines.join('\n')}\n-----END PUBLIC KEY-----`;
  }

  function parsePemToBuffer(pem) {
    const b64 = pem
      .replace(/-----BEGIN [A-Z ]+-----/g, '')
      .replace(/-----END [A-Z ]+-----/g, '')
      .replace(/\s+/g, '');
    return base64ToArrayBuffer(b64);
  }

  async function generateRsaKeyPair() {
    const keyPair = await crypto.subtle.generateKey(
      {
        name: "RSASSA-PKCS1-v1_5",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256"
      },
      true, // extractable
      ["sign", "verify"]
    );

    const privateBuffer = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
    const publicBuffer = await crypto.subtle.exportKey("spki", keyPair.publicKey);

    return {
      privatePem: exportPemPrivate(privateBuffer),
      publicPem: exportPemPublic(publicBuffer)
    };
  }

  // ==========================================================================
  // Standard JWT Sign / Verify Core
  // ==========================================================================

  function getHmacHashAlg(alg) {
    switch (alg) {
      case 'HS256': return 'SHA-256';
      case 'HS384': return 'SHA-384';
      case 'HS512': return 'SHA-512';
      default: return 'SHA-256';
    }
  }

  function isRsaAlg(alg) {
    return alg === 'RS256';
  }

  async function signJwtHmac(headerObj, payloadObj, rawKey, keyFormat) {
    const headerStr = JSON.stringify(headerObj);
    const payloadStr = JSON.stringify(payloadObj);
    
    const encoder = new TextEncoder();
    const headerBase64 = base64urlEncode(encoder.encode(headerStr).buffer);
    const payloadBase64 = base64urlEncode(encoder.encode(payloadStr).buffer);
    
    const messageStr = `${headerBase64}.${payloadBase64}`;
    const messageData = encoder.encode(messageStr);

    let keyBytes;
    try {
      keyBytes = await prepareKeyBytes(rawKey, keyFormat, false);
    } catch (e) {
      throw new Error(`Secret key error: ${e.message}`);
    }

    const hashName = getHmacHashAlg(headerObj.alg);
    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      keyBytes,
      { name: "HMAC", hash: { name: hashName } },
      false,
      ["sign"]
    );

    const signatureBuffer = await crypto.subtle.sign(
      "HMAC",
      cryptoKey,
      messageData
    );

    const signatureBase64 = base64urlEncode(signatureBuffer);
    return {
      token: `${messageStr}.${signatureBase64}`,
      headerBase64,
      payloadBase64,
      signatureBase64
    };
  }

  async function signJwtRsa(headerObj, payloadObj, privatePem) {
    const headerStr = JSON.stringify(headerObj);
    const payloadStr = JSON.stringify(payloadObj);

    const encoder = new TextEncoder();
    const headerBase64 = base64urlEncode(encoder.encode(headerStr).buffer);
    const payloadBase64 = base64urlEncode(encoder.encode(payloadStr).buffer);

    const messageStr = `${headerBase64}.${payloadBase64}`;
    const messageData = encoder.encode(messageStr);

    const keyBuffer = parsePemToBuffer(privatePem);
    const cryptoKey = await crypto.subtle.importKey(
      "pkcs8",
      keyBuffer,
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["sign"]
    );

    const signatureBuffer = await crypto.subtle.sign(
      "RSASSA-PKCS1-v1_5",
      cryptoKey,
      messageData
    );

    const signatureBase64 = base64urlEncode(signatureBuffer);
    return {
      token: `${messageStr}.${signatureBase64}`,
      headerBase64,
      payloadBase64,
      signatureBase64
    };
  }

  async function verifyJwtHmac(token, rawKey, keyFormat) {
    const parts = token.trim().split('.');
    if (parts.length !== 3) {
      throw new Error('JWT must have 3 parts separated by dots');
    }

    const [headerBase64, payloadBase64, signatureBase64] = parts;
    const decoder = new TextDecoder();
    
    let headerObj, payloadObj;
    try {
      headerObj = JSON.parse(decoder.decode(base64urlDecode(headerBase64)));
    } catch (e) {
      throw new Error('Header is not valid JSON');
    }

    try {
      payloadObj = JSON.parse(decoder.decode(base64urlDecode(payloadBase64)));
    } catch (e) {
      throw new Error('Payload is not valid JSON');
    }

    const alg = headerObj.alg || 'HS256';
    const hashName = getHmacHashAlg(alg);

    let keyBytes;
    try {
      keyBytes = await prepareKeyBytes(rawKey, keyFormat, false);
    } catch (e) {
      throw new Error(`Secret key error: ${e.message}`);
    }

    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      keyBytes,
      { name: "HMAC", hash: { name: hashName } },
      false,
      ["verify"]
    );

    const messageData = new TextEncoder().encode(`${headerBase64}.${payloadBase64}`);
    const signatureBytes = new Uint8Array(base64urlDecode(signatureBase64));

    const isValid = await crypto.subtle.verify(
      "HMAC",
      cryptoKey,
      signatureBytes,
      messageData
    );

    return {
      isValid,
      headerObj,
      payloadObj,
      headerBase64,
      payloadBase64,
      signatureBase64
    };
  }

  async function verifyJwtRsa(token, publicPem) {
    const parts = token.trim().split('.');
    if (parts.length !== 3) {
      throw new Error('JWT must have 3 parts separated by dots');
    }

    const [headerBase64, payloadBase64, signatureBase64] = parts;
    const decoder = new TextDecoder();

    let headerObj, payloadObj;
    try {
      headerObj = JSON.parse(decoder.decode(base64urlDecode(headerBase64)));
    } catch (e) {
      throw new Error('Header is not valid JSON');
    }
    try {
      payloadObj = JSON.parse(decoder.decode(base64urlDecode(payloadBase64)));
    } catch (e) {
      throw new Error('Payload is not valid JSON');
    }

    const keyBuffer = parsePemToBuffer(publicPem);
    const cryptoKey = await crypto.subtle.importKey(
      "spki",
      keyBuffer,
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["verify"]
    );

    const messageData = new TextEncoder().encode(`${headerBase64}.${payloadBase64}`);
    const signatureBytes = new Uint8Array(base64urlDecode(signatureBase64));

    const isValid = await crypto.subtle.verify(
      "RSASSA-PKCS1-v1_5",
      cryptoKey,
      signatureBytes,
      messageData
    );

    return {
      isValid,
      headerObj,
      payloadObj,
      headerBase64,
      payloadBase64,
      signatureBase64
    };
  }

  // ==========================================================================
  // AES-256-GCM Encrypt / Decrypt Core
  // ==========================================================================

  async function encryptGcm(plaintext, rawKey, keyFormat, deriveSha256, customIvHex) {
    let keyBytes;
    try {
      keyBytes = await prepareKeyBytes(rawKey, keyFormat, deriveSha256);
    } catch (e) {
      throw new Error(`Key prep failed: ${e.message}`);
    }

    // Resolve IV
    let iv;
    if (customIvHex && customIvHex.trim().length > 0) {
      const cleanIv = customIvHex.trim();
      if (cleanIv.length !== 24) {
        throw new Error('Custom IV must be exactly 24 hex characters (12 bytes)');
      }
      iv = hexToBuf(cleanIv);
    } else {
      iv = crypto.getRandomValues(new Uint8Array(12));
    }

    let aesKeyBytes = keyBytes;
    if (aesKeyBytes.length !== 16 && aesKeyBytes.length !== 24 && aesKeyBytes.length !== 32) {
      const padded = new Uint8Array(32);
      padded.set(aesKeyBytes.slice(0, 32));
      aesKeyBytes = padded;
    }

    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      aesKeyBytes,
      { name: "AES-GCM" },
      false,
      ["encrypt"]
    );

    const encoder = new TextEncoder();
    const encodedPlaintext = encoder.encode(plaintext);

    const encryptedBuffer = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv },
      cryptoKey,
      encodedPlaintext
    );

    const encryptedBytes = new Uint8Array(encryptedBuffer);
    const ciphertextBytes = encryptedBytes.slice(0, -16);
    const tagBytes = encryptedBytes.slice(-16);

    const ivHex = bufToHex(iv);
    const ciphertextHex = bufToHex(ciphertextBytes);
    const tagHex = bufToHex(tagBytes);

    return `${ivHex}:${ciphertextHex}:${tagHex}`;
  }

  async function decryptGcm(encryptedToken, rawKey, keyFormat, deriveSha256) {
    const parts = encryptedToken.trim().split(':');
    if (parts.length !== 3) {
      throw new Error('Encrypted token must have 3 colon-separated segments (iv:ciphertext:tag)');
    }

    const [ivHex, ciphertextHex, tagHex] = parts;
    if (ivHex.length !== 24) {
      throw new Error(`Invalid IV length: expected 24 hex characters (12 bytes), got ${ivHex.length}`);
    }
    if (tagHex.length !== 32) {
      throw new Error(`Invalid Tag length: expected 32 hex characters (16 bytes), got ${tagHex.length}`);
    }

    const ivBytes = hexToBuf(ivHex);
    const ciphertextBytes = hexToBuf(ciphertextHex);
    const tagBytes = hexToBuf(tagHex);

    const combinedBytes = new Uint8Array(ciphertextBytes.length + tagBytes.length);
    combinedBytes.set(ciphertextBytes, 0);
    combinedBytes.set(tagBytes, ciphertextBytes.length);

    let keyBytes;
    try {
      keyBytes = await prepareKeyBytes(rawKey, keyFormat, deriveSha256);
    } catch (e) {
      throw new Error(`Key preparation failed: ${e.message}`);
    }

    let aesKeyBytes = keyBytes;
    if (aesKeyBytes.length !== 16 && aesKeyBytes.length !== 24 && aesKeyBytes.length !== 32) {
      const padded = new Uint8Array(32);
      padded.set(aesKeyBytes.slice(0, 32));
      aesKeyBytes = padded;
    }

    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      aesKeyBytes,
      { name: "AES-GCM" },
      false,
      ["decrypt"]
    );

    const decryptedBuffer = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: ivBytes },
      cryptoKey,
      combinedBytes
    );

    const decoder = new TextDecoder();
    return {
      plaintext: decoder.decode(decryptedBuffer),
      ivHex,
      ciphertextHex,
      tagHex,
      ciphertextLength: ciphertextBytes.length
    };
  }

  // ==========================================================================
  // HMAC Key Strength Advisor
  // ==========================================================================

  function evaluateKeyStrength(key, keyFormat, alg) {
    if (!key) {
      return { level: 'critical', score: 0, label: 'No Key', hints: ['Enter a signing key to begin.'] };
    }

    let byteLength;
    if (keyFormat === 'hex') {
      const cleaned = key.replace(/\s+/g, '');
      byteLength = Math.floor(cleaned.length / 2);
    } else {
      byteLength = new TextEncoder().encode(key).length;
    }

    const bitLength = byteLength * 8;
    const hints = [];

    // Recommended minimum: equal to hash output (32 for SHA-256, 48 for SHA-384, 64 for SHA-512)
    const recommendedBytes = { HS256: 32, HS384: 48, HS512: 64 };
    const recommended = recommendedBytes[alg] || 32;
    const recommendedBits = recommended * 8;

    // Scoring logic
    let score = 0;
    let level = 'critical';

    if (bitLength >= recommendedBits) {
      score = 100;
      level = 'strong';
    } else if (bitLength >= recommendedBits * 0.75) {
      score = 75;
      level = 'good';
    } else if (bitLength >= recommendedBits * 0.5) {
      score = 50;
      level = 'weak';
    } else if (bitLength > 0) {
      score = Math.max(10, Math.round((bitLength / recommendedBits) * 50));
      level = 'critical';
    }

    // Check for common weak patterns (text keys only)
    if (keyFormat !== 'hex') {
      if (/^(.)\1+$/.test(key)) {
        score = Math.min(score, 15);
        level = 'critical';
        hints.push('Key is a single repeated character — extremely weak.');
      }
      if (/^(password|secret|123456|admin|test|key)/i.test(key)) {
        score = Math.min(score, 30);
        level = score <= 30 ? 'critical' : level;
        hints.push('Key contains a common dictionary word.');
      }
      const hasUpper = /[A-Z]/.test(key);
      const hasLower = /[a-z]/.test(key);
      const hasDigit = /[0-9]/.test(key);
      const hasSpecial = /[^A-Za-z0-9]/.test(key);
      const charClasses = [hasUpper, hasLower, hasDigit, hasSpecial].filter(Boolean).length;
      if (charClasses < 3 && keyFormat === 'text') {
        hints.push(`Low character diversity (${charClasses}/4 classes). Mix upper, lower, digits, and symbols.`);
      }
    }

    if (bitLength < recommendedBits) {
      hints.push(`${bitLength}-bit key. ${alg} recommends ≥${recommendedBits}-bit (${recommended} bytes).`);
    } else {
      hints.push(`${bitLength}-bit key meets ${alg} recommendation of ≥${recommendedBits}-bit.`);
    }

    const label = level === 'strong' ? 'Strong' : level === 'good' ? 'Good' : level === 'weak' ? 'Weak' : 'Critical';
    return { level, score, label, hints };
  }

  function renderStrengthAdvisor() {
    const alg = els.jwtAlg.value;
    if (isRsaAlg(alg)) {
      els.strengthAdvisor.style.display = 'none';
      return;
    }
    els.strengthAdvisor.style.display = '';

    const key = els.jwtKey.value;
    const keyFormat = els.keyFormatHex.checked ? 'hex' : 'text';
    const result = evaluateKeyStrength(key, keyFormat, alg);

    els.strengthValue.textContent = result.label;
    els.strengthValue.className = `strength-value ${result.level}`;
    els.strengthFill.className = `strength-fill ${result.level}`;
    els.strengthFill.style.width = `${result.score}%`;
    els.strengthHints.textContent = result.hints.join(' ');
  }

  // ==========================================================================
  // Token Validation Checklist
  // ==========================================================================

  function runValidationChecklist(headerObj, payloadObj, signatureValid) {
    const checks = [];
    const now = Math.floor(Date.now() / 1000);

    // 1. Structure check
    checks.push({
      label: 'Valid 3-part JWT structure',
      status: (headerObj && payloadObj) ? 'pass' : 'fail'
    });

    // 2. Algorithm present
    checks.push({
      label: `Algorithm specified (${headerObj?.alg || 'none'})`,
      status: headerObj?.alg ? 'pass' : 'fail'
    });

    // 3. Type claim
    checks.push({
      label: 'Type claim (typ: "JWT")',
      status: headerObj?.typ === 'JWT' ? 'pass' : 'warn'
    });

    // 4. Signature
    checks.push({
      label: 'Signature verification',
      status: signatureValid === true ? 'pass' : signatureValid === false ? 'fail' : 'na'
    });

    // 5. Issued At
    checks.push({
      label: 'Issued At (iat) present',
      status: typeof payloadObj?.iat === 'number' ? 'pass' : 'warn'
    });

    // 6. Expiration
    if (typeof payloadObj?.exp === 'number') {
      checks.push({
        label: payloadObj.exp > now ? `Token not expired (exp: ${new Date(payloadObj.exp * 1000).toISOString()})` : `Token EXPIRED (exp: ${new Date(payloadObj.exp * 1000).toISOString()})`,
        status: payloadObj.exp > now ? 'pass' : 'fail'
      });
    } else {
      checks.push({
        label: 'Expiration (exp) not set',
        status: 'warn'
      });
    }

    // 7. Subject
    checks.push({
      label: 'Subject (sub) present',
      status: payloadObj?.sub ? 'pass' : 'warn'
    });

    // 8. Issuer
    checks.push({
      label: 'Issuer (iss) present',
      status: payloadObj?.iss ? 'pass' : 'na'
    });

    // 9. nbf (Not Before)
    if (typeof payloadObj?.nbf === 'number') {
      checks.push({
        label: payloadObj.nbf <= now ? 'Not Before (nbf) — token is active' : 'Not Before (nbf) — token not yet valid',
        status: payloadObj.nbf <= now ? 'pass' : 'warn'
      });
    }

    return checks;
  }

  function renderValidationChecklist(checks) {
    els.checklistItems.innerHTML = '';
    let passCount = 0;

    checks.forEach(check => {
      const item = document.createElement('div');
      item.className = 'checklist-item';

      const icon = document.createElement('span');
      icon.className = `check-icon ${check.status}`;
      icon.textContent = check.status === 'pass' ? '✓' : check.status === 'fail' ? '✗' : check.status === 'warn' ? '!' : '—';

      const label = document.createElement('span');
      label.className = `check-label ${check.status}`;
      label.textContent = check.label;

      item.appendChild(icon);
      item.appendChild(label);
      els.checklistItems.appendChild(item);

      if (check.status === 'pass') passCount++;
    });

    els.checklistScore.textContent = `${passCount} / ${checks.length}`;
  }

  // ==========================================================================
  // App UI & Controller Logic
  // ==========================================================================

  /**
   * Enhanced toast with type-based styling and progress bar.
   * @param {string} message
   * @param {'success'|'error'|'info'} type
   */
  function showToast(message, typeOrError = 'success') {
    // Support legacy boolean second param: true = error, false/undefined = success
    let type = typeOrError;
    if (typeof typeOrError === 'boolean') {
      type = typeOrError ? 'error' : 'success';
    }

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;

    const msg = document.createElement('span');
    msg.className = 'toast-message';
    msg.textContent = message;

    const progress = document.createElement('div');
    progress.className = 'toast-progress';

    toast.appendChild(msg);
    toast.appendChild(progress);

    els.toastContainer.appendChild(toast);

    // Auto dismiss after animation completes
    setTimeout(() => {
      toast.classList.add('leaving');
      toast.addEventListener('animationend', () => toast.remove());
    }, 3200);
  }

  function tryParseJson(str) {
    try {
      return JSON.parse(str);
    } catch (e) {
      return null;
    }
  }

  /** Render TTL Bar based on expiration claim */
  function updateTtlIndicator(payloadObj) {
    if (!payloadObj || typeof payloadObj !== 'object') {
      els.ttlStatusBar.classList.add('hidden');
      return;
    }

    const exp = payloadObj.exp;
    if (!exp || typeof exp !== 'number') {
      els.ttlStatusBar.classList.add('hidden');
      return;
    }

    const currentSeconds = Math.floor(Date.now() / 1000);
    const diff = exp - currentSeconds;

    els.ttlStatusBar.classList.remove('hidden');
    if (diff > 0) {
      els.ttlStatusBar.classList.remove('expired');
      els.ttlText.textContent = `Token active: Expires in ${formatDuration(diff)}`;
    } else {
      els.ttlStatusBar.classList.add('expired');
      els.ttlText.textContent = `Token expired ${formatDuration(Math.abs(diff))} ago`;
    }
  }

  function formatDuration(seconds) {
    if (seconds < 60) return `${seconds}s`;
    const minutes = Math.floor(seconds / 60);
    if (minutes < 60) return `${minutes}m ${seconds % 60}s`;
    const hours = Math.floor(minutes / 60);
    if (hours < 24) return `${hours}h ${minutes % 60}m`;
    const days = Math.floor(hours / 24);
    return `${days}d ${hours % 24}h`;
  }

  // ==========================================================================
  // Theme Toggle (Dark ↔ Light)
  // ==========================================================================

  function initTheme() {
    const saved = localStorage.getItem('jwt-cipher-theme');
    if (saved === 'light') {
      document.documentElement.setAttribute('data-theme', 'light');
    }
    // Default is dark, no attribute needed
  }

  function toggleTheme() {
    const current = document.documentElement.getAttribute('data-theme');
    const isLight = current !== 'light';
    if (isLight) {
      document.documentElement.setAttribute('data-theme', 'light');
    } else {
      document.documentElement.removeAttribute('data-theme');
    }
    localStorage.setItem('jwt-cipher-theme', isLight ? 'light' : 'dark');
    showToast(isLight ? 'Switched to Light Mode' : 'Switched to Dark Mode', 'info');
  }

  if (els.btnThemeToggle) {
    els.btnThemeToggle.addEventListener('click', toggleTheme);
  }

  // ==========================================================================
  // Algorithm Toggle (HMAC vs RSA fields)
  // ==========================================================================

  function syncAlgorithmUI() {
    const alg = els.jwtAlg.value;
    if (isRsaAlg(alg)) {
      els.hmacKeyGroup.classList.add('hidden');
      els.rsaKeyGroup.classList.remove('hidden');
    } else {
      els.hmacKeyGroup.classList.remove('hidden');
      els.rsaKeyGroup.classList.add('hidden');
    }
    // Update header JSON to match selected algorithm
    const headerText = els.jwtHeader.value.trim();
    const headerJson = tryParseJson(headerText);
    if (headerJson && headerJson.alg !== alg) {
      headerJson.alg = alg;
      els.jwtHeader.value = JSON.stringify(headerJson, null, 2);
    }
    renderStrengthAdvisor();
  }

  // ==========================================================================
  // Panel Navigation with Sliding Indicator
  // ==========================================================================

  const allPanels = [
    { btn: els.tabBtnStandard, panel: els.panelStandard },
    { btn: els.tabBtnEncrypted, panel: els.panelEncrypted },
    { btn: els.tabBtnUtilities, panel: els.panelUtilities },
    { btn: els.tabBtnConverter, panel: els.panelConverter },
    { btn: els.tabBtnHash, panel: els.panelHash },
    { btn: els.tabBtnPassword, panel: els.panelPassword }
  ];

  function moveIndicator(activeBtn) {
    if (!els.tabIndicator || !activeBtn) return;
    const navRect = els.navBar.getBoundingClientRect();
    const btnRect = activeBtn.getBoundingClientRect();
    els.tabIndicator.style.width = `${btnRect.width}px`;
    els.tabIndicator.style.left = `${btnRect.left - navRect.left}px`;
  }

  function switchPanel(panelId, activeTabBtn) {
    allPanels.forEach(({ btn, panel }) => {
      if (!btn || !panel) return;
      btn.classList.remove('active');
      btn.setAttribute('aria-selected', 'false');
      if (panel.id === panelId) {
        panel.style.display = 'block';
        panel.classList.add('active');
      } else {
        panel.style.display = 'none';
        panel.classList.remove('active');
      }
    });
    if (activeTabBtn) {
      activeTabBtn.classList.add('active');
      activeTabBtn.setAttribute('aria-selected', 'true');
      moveIndicator(activeTabBtn);
    }
  }

  allPanels.forEach(({ btn, panel }) => {
    if (btn && panel) {
      btn.addEventListener('click', () => switchPanel(panel.id, btn));
    }
  });

  // Recalculate indicator on resize
  window.addEventListener('resize', () => {
    const activeBtn = els.navBar.querySelector('.tab-item.active');
    if (activeBtn) moveIndicator(activeBtn);
  });

  function initStandardPanel() {
    els.jwtHeader.value = JSON.stringify(defaultHeader, null, 2);
    // Load default template (session)
    els.jwtPayload.value = JSON.stringify(TEMPLATES.session, null, 2);
    
    syncAlgorithmUI();
    updateEncodedJwtFromEditors();
  }

  function setupKeyVisibilityToggle(btn, input) {
    if (!btn || !input) return;
    btn.addEventListener('click', () => {
      const isPassword = input.type === 'password';
      input.type = isPassword ? 'text' : 'password';
      btn.querySelector('.eye-svg').style.opacity = isPassword ? '0.5' : '1.0';
    });
  }
  setupKeyVisibilityToggle(els.btnToggleKeyVisibility, els.jwtKey);
  setupKeyVisibilityToggle(els.btnToggleEncKeyVisibility, els.encKey);
  setupKeyVisibilityToggle(els.btnToggleDecKeyVisibility, els.decKey);

  // ==========================================================================
  // Token Size Counter
  // ==========================================================================

  function updateTokenSize(token) {
    if (els.tokenSizeBadge) {
      const bytes = new TextEncoder().encode(token || '').length;
      els.tokenSizeBadge.textContent = `${bytes} bytes`;
    }
  }

  // ==========================================================================
  // JSON Prettify / Minify
  // ==========================================================================

  if (els.btnPrettify) {
    els.btnPrettify.addEventListener('click', () => {
      const json = tryParseJson(els.jwtPayload.value.trim());
      if (json) {
        els.jwtPayload.value = JSON.stringify(json, null, 2);
        showToast('Payload prettified', 'info');
      } else {
        showToast('Cannot prettify: invalid JSON', true);
      }
    });
  }

  if (els.btnMinify) {
    els.btnMinify.addEventListener('click', () => {
      const json = tryParseJson(els.jwtPayload.value.trim());
      if (json) {
        els.jwtPayload.value = JSON.stringify(json);
        showToast('Payload minified', 'info');
      } else {
        showToast('Cannot minify: invalid JSON', true);
      }
    });
  }

  // ==========================================================================
  // Quick Claim Inserters
  // ==========================================================================

  document.querySelectorAll('.claim-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const claim = btn.getAttribute('data-claim');
      if (!claim) return;

      const txt = els.jwtPayload.value.trim();
      let payload = tryParseJson(txt);
      if (!payload) {
        showToast('Fix JSON payload syntax first!', true);
        return;
      }

      const now = Math.floor(Date.now() / 1000);
      switch (claim) {
        case 'jti':
          // Generate a random UUID-like string
          payload.jti = crypto.getRandomValues(new Uint8Array(16))
            .reduce((s, b) => s + b.toString(16).padStart(2, '0'), '');
          break;
        case 'nbf':
          payload.nbf = now;
          break;
        case 'aud':
          if (!payload.aud) payload.aud = 'https://api.example.com';
          break;
        case 'iss':
          if (!payload.iss) payload.iss = 'https://auth.example.com';
          break;
        case 'sub':
          if (!payload.sub) payload.sub = 'user_' + Math.random().toString(36).substring(2, 10);
          break;
      }

      els.jwtPayload.value = JSON.stringify(payload, null, 2);
      updateEncodedJwtFromEditors();
      showToast(`Inserted claim: ${claim}`, 'info');
    });
  });

  // ==========================================================================
  // QR Code Generator (Minimal inline implementation)
  // ==========================================================================

  /**
   * Minimal QR Code generator using canvas.
   * Implements a simplified version of QR encoding (Mode Byte, ECC Level L).
   * For tokens > ~2950 chars, we truncate and show a warning.
   */
  const QRCode = (() => {
    // Galois Field GF(256) arithmetic for Reed-Solomon error correction
    const GF256_EXP = new Uint8Array(512);
    const GF256_LOG = new Uint8Array(256);

    // Initialize GF(256) lookup tables
    (function initGF() {
      let x = 1;
      for (let i = 0; i < 255; i++) {
        GF256_EXP[i] = x;
        GF256_LOG[x] = i;
        x = (x << 1) ^ (x >= 128 ? 0x11d : 0);
      }
      for (let i = 255; i < 512; i++) {
        GF256_EXP[i] = GF256_EXP[i - 255];
      }
    })();

    function gfMul(a, b) {
      if (a === 0 || b === 0) return 0;
      return GF256_EXP[(GF256_LOG[a] + GF256_LOG[b]) % 255];
    }

    // Generate Reed-Solomon generator polynomial
    function rsGenPoly(nsym) {
      let g = [1];
      for (let i = 0; i < nsym; i++) {
        const ng = new Array(g.length + 1).fill(0);
        for (let j = 0; j < g.length; j++) {
          ng[j] ^= g[j];
          ng[j + 1] ^= gfMul(g[j], GF256_EXP[i]);
        }
        g = ng;
      }
      return g;
    }

    // Reed-Solomon encode
    function rsEncode(data, nsym) {
      const gen = rsGenPoly(nsym);
      const res = new Array(data.length + nsym).fill(0);
      for (let i = 0; i < data.length; i++) res[i] = data[i];

      for (let i = 0; i < data.length; i++) {
        const coef = res[i];
        if (coef !== 0) {
          for (let j = 1; j < gen.length; j++) {
            res[i + j] ^= gfMul(gen[j], coef);
          }
        }
      }
      return res.slice(data.length);
    }

    // QR version capacity table (byte mode, ECC Level L)
    // [version, totalCodewords, eccCodewordsPerBlock, numBlocks, dataCapacity]
    const VERSION_TABLE = [
      [1, 26, 7, 1, 17],
      [2, 44, 10, 1, 32],
      [3, 70, 15, 1, 53],
      [4, 100, 20, 1, 78],
      [5, 134, 26, 1, 106],
      [6, 172, 18, 2, 134],
      [7, 196, 20, 2, 154],
      [8, 230, 24, 2, 192],
      [9, 271, 30, 2, 230],
      [10, 321, 18, 4, 271],
      [11, 367, 20, 4, 311],
      [12, 425, 24, 4, 362],
      [13, 458, 26, 4, 412],
      [14, 520, 30, 4, 450],
      [15, 586, 22, 6, 504],
      [16, 644, 24, 6, 560],
      [17, 718, 28, 6, 624],
      [18, 792, 30, 6, 666],
      [19, 858, 26, 8, 711],
      [20, 929, 28, 8, 779],
      [21, 1003, 30, 8, 857],
      [22, 1091, 28, 8, 911],
      [23, 1171, 30, 8, 997],
      [24, 1273, 30, 8, 1059],
      [25, 1367, 26, 10, 1125],
      [26, 1465, 28, 10, 1190],
      [27, 1528, 30, 10, 1264],
      [28, 1628, 30, 10, 1370],
      [29, 1732, 30, 10, 1452],
      [30, 1840, 30, 10, 1538],
      [31, 1952, 30, 10, 1628],
      [32, 2068, 30, 10, 1722],
      [33, 2188, 30, 10, 1809],
      [34, 2303, 30, 10, 1911],
      [35, 2431, 30, 12, 2000],
      [36, 2563, 30, 12, 2099],
      [37, 2699, 30, 12, 2213],
      [38, 2809, 30, 12, 2331],
      [39, 2953, 30, 12, 2453],
      [40, 3057, 30, 12, 2563],
    ];

    function selectVersion(dataLen) {
      for (const [ver, total, eccPerBlock, blocks, cap] of VERSION_TABLE) {
        if (dataLen <= cap) {
          return { version: ver, totalCodewords: total, eccPerBlock, blocks, dataCapacity: cap };
        }
      }
      return null; // Data too large
    }

    // Create data codewords from byte data
    function createDataCodewords(bytes, dataCapacity) {
      const bits = [];

      // Mode indicator: Byte mode = 0100
      bits.push(0, 1, 0, 0);

      // Character count indicator (8 bits for version 1-9, 16 bits for 10+)
      const countBits = bytes.length < 256 ? 8 : 16;
      for (let i = countBits - 1; i >= 0; i--) {
        bits.push((bytes.length >> i) & 1);
      }

      // Data
      for (const b of bytes) {
        for (let i = 7; i >= 0; i--) {
          bits.push((b >> i) & 1);
        }
      }

      // Terminator (up to 4 zeros)
      const maxBits = dataCapacity * 8;
      const termLen = Math.min(4, maxBits - bits.length);
      for (let i = 0; i < termLen; i++) bits.push(0);

      // Pad to byte boundary
      while (bits.length % 8 !== 0) bits.push(0);

      // Pad bytes
      const padBytes = [0xEC, 0x11];
      let padIdx = 0;
      while (bits.length < maxBits) {
        const pb = padBytes[padIdx % 2];
        for (let i = 7; i >= 0; i--) bits.push((pb >> i) & 1);
        padIdx++;
      }

      // Convert bits to bytes
      const codewords = [];
      for (let i = 0; i < bits.length; i += 8) {
        let byte = 0;
        for (let j = 0; j < 8; j++) byte = (byte << 1) | (bits[i + j] || 0);
        codewords.push(byte);
      }

      return codewords;
    }

    // Interleave data and error correction codewords
    function interleave(dataCodewords, eccPerBlock, numBlocks) {
      const blockSize = Math.floor(dataCodewords.length / numBlocks);
      const extraBlocks = dataCodewords.length % numBlocks;

      const dataBlocks = [];
      const eccBlocks = [];
      let offset = 0;

      for (let b = 0; b < numBlocks; b++) {
        const thisBlockSize = blockSize + (b >= numBlocks - extraBlocks ? 1 : 0);
        const block = dataCodewords.slice(offset, offset + thisBlockSize);
        dataBlocks.push(block);
        eccBlocks.push(rsEncode(block, eccPerBlock));
        offset += thisBlockSize;
      }

      // Interleave data
      const result = [];
      const maxDataLen = Math.max(...dataBlocks.map(b => b.length));
      for (let i = 0; i < maxDataLen; i++) {
        for (const block of dataBlocks) {
          if (i < block.length) result.push(block[i]);
        }
      }

      // Interleave ECC
      for (let i = 0; i < eccPerBlock; i++) {
        for (const block of eccBlocks) {
          if (i < block.length) result.push(block[i]);
        }
      }

      return result;
    }

    // Alignment pattern positions for each version
    function getAlignmentPositions(version) {
      if (version === 1) return [];
      const positions = [6];
      const last = version * 4 + 10;
      const count = Math.floor(version / 7) + 2;
      const step = Math.ceil((last - 6) / (count - 1));
      // Ensure step is even
      const adjustedStep = step % 2 === 0 ? step : step + 1;
      for (let i = 1; i < count; i++) {
        positions.push(last - (count - 1 - i) * adjustedStep);
      }
      return positions;
    }

    // Build the QR matrix
    function buildMatrix(version, codewords) {
      const size = version * 4 + 17;
      const matrix = Array.from({ length: size }, () => new Int8Array(size).fill(-1));
      // -1 = empty, 0 = white, 1 = black

      // Place finder patterns
      function placeFinderPattern(row, col) {
        for (let r = -1; r <= 7; r++) {
          for (let c = -1; c <= 7; c++) {
            const rr = row + r, cc = col + c;
            if (rr < 0 || rr >= size || cc < 0 || cc >= size) continue;
            if (r >= 0 && r <= 6 && c >= 0 && c <= 6) {
              if (r === 0 || r === 6 || c === 0 || c === 6 || (r >= 2 && r <= 4 && c >= 2 && c <= 4)) {
                matrix[rr][cc] = 1;
              } else {
                matrix[rr][cc] = 0;
              }
            } else {
              matrix[rr][cc] = 0; // Separator
            }
          }
        }
      }

      placeFinderPattern(0, 0);
      placeFinderPattern(0, size - 7);
      placeFinderPattern(size - 7, 0);

      // Timing patterns
      for (let i = 8; i < size - 8; i++) {
        if (matrix[6][i] === -1) matrix[6][i] = i % 2 === 0 ? 1 : 0;
        if (matrix[i][6] === -1) matrix[i][6] = i % 2 === 0 ? 1 : 0;
      }

      // Alignment patterns
      if (version >= 2) {
        const positions = getAlignmentPositions(version);
        for (const r of positions) {
          for (const c of positions) {
            // Skip if overlapping with finder patterns
            if (r <= 8 && c <= 8) continue;
            if (r <= 8 && c >= size - 8) continue;
            if (r >= size - 8 && c <= 8) continue;

            for (let dr = -2; dr <= 2; dr++) {
              for (let dc = -2; dc <= 2; dc++) {
                const rr = r + dr, cc = c + dc;
                if (rr >= 0 && rr < size && cc >= 0 && cc < size) {
                  if (Math.abs(dr) === 2 || Math.abs(dc) === 2 || (dr === 0 && dc === 0)) {
                    matrix[rr][cc] = 1;
                  } else {
                    matrix[rr][cc] = 0;
                  }
                }
              }
            }
          }
        }
      }

      // Reserve format info areas
      for (let i = 0; i < 8; i++) {
        if (matrix[8][i] === -1) matrix[8][i] = 0;
        if (matrix[i][8] === -1) matrix[i][8] = 0;
        if (matrix[8][size - 1 - i] === -1) matrix[8][size - 1 - i] = 0;
        if (matrix[size - 1 - i][8] === -1) matrix[size - 1 - i][8] = 0;
      }
      matrix[8][8] = 0;

      // Dark module
      matrix[size - 8][8] = 1;

      // Version info (version >= 7)
      if (version >= 7) {
        // Simplified: reserve version info areas
        for (let i = 0; i < 6; i++) {
          for (let j = 0; j < 3; j++) {
            matrix[i][size - 11 + j] = 0;
            matrix[size - 11 + j][i] = 0;
          }
        }
      }

      // Place data bits in zigzag pattern
      const bits = [];
      for (const cw of codewords) {
        for (let i = 7; i >= 0; i--) bits.push((cw >> i) & 1);
      }

      let bitIdx = 0;
      let upward = true;

      for (let right = size - 1; right >= 1; right -= 2) {
        if (right === 6) right = 5; // Skip timing column

        const rows = upward ? Array.from({ length: size }, (_, i) => size - 1 - i) : Array.from({ length: size }, (_, i) => i);

        for (const row of rows) {
          for (const col of [right, right - 1]) {
            if (col < 0 || col >= size) continue;
            if (matrix[row][col] !== -1) continue;

            if (bitIdx < bits.length) {
              matrix[row][col] = bits[bitIdx];
              bitIdx++;
            } else {
              matrix[row][col] = 0;
            }
          }
        }

        upward = !upward;
      }

      // Apply mask pattern 0 (checkerboard: (row + col) % 2 === 0)
      for (let r = 0; r < size; r++) {
        for (let c = 0; c < size; c++) {
          // Only apply to data modules (skip function patterns)
          if (isDataModule(r, c, size, version)) {
            if ((r + c) % 2 === 0) {
              matrix[r][c] ^= 1;
            }
          }
        }
      }

      // Write format info for mask 0, ECC level L
      // Pre-computed: ECC L (01), mask 0 (000) → format info = 0x77c4
      const formatInfo = 0x77c4;
      writeFormatInfo(matrix, size, formatInfo);

      // Write version info (version >= 7)
      if (version >= 7) {
        writeVersionInfo(matrix, size, version);
      }

      return matrix;
    }

    function isDataModule(row, col, size, version) {
      // Finder patterns + separators
      if (row <= 8 && col <= 8) return false;
      if (row <= 8 && col >= size - 8) return false;
      if (row >= size - 8 && col <= 8) return false;

      // Timing patterns
      if (row === 6 || col === 6) return false;

      // Format info
      if (row === 8 && (col <= 8 || col >= size - 8)) return false;
      if (col === 8 && (row <= 8 || row >= size - 8)) return false;

      // Dark module
      if (row === size - 8 && col === 8) return false;

      // Alignment patterns
      if (version >= 2) {
        const positions = getAlignmentPositions(version);
        for (const ar of positions) {
          for (const ac of positions) {
            if (ar <= 8 && ac <= 8) continue;
            if (ar <= 8 && ac >= size - 8) continue;
            if (ar >= size - 8 && ac <= 8) continue;
            if (Math.abs(row - ar) <= 2 && Math.abs(col - ac) <= 2) return false;
          }
        }
      }

      // Version info
      if (version >= 7) {
        if (row < 6 && col >= size - 11 && col < size - 8) return false;
        if (col < 6 && row >= size - 11 && row < size - 8) return false;
      }

      return true;
    }

    function writeFormatInfo(matrix, size, info) {
      const bits = [];
      for (let i = 14; i >= 0; i--) bits.push((info >> i) & 1);

      // Around top-left finder
      const positions1 = [
        [0, 8], [1, 8], [2, 8], [3, 8], [4, 8], [5, 8],
        [7, 8], [8, 8], [8, 7], [8, 5], [8, 4], [8, 3],
        [8, 2], [8, 1], [8, 0]
      ];

      // Around other finders
      const positions2 = [
        [8, size - 1], [8, size - 2], [8, size - 3], [8, size - 4],
        [8, size - 5], [8, size - 6], [8, size - 7], [8, size - 8],
        [size - 7, 8], [size - 6, 8], [size - 5, 8], [size - 4, 8],
        [size - 3, 8], [size - 2, 8], [size - 1, 8]
      ];

      for (let i = 0; i < 15; i++) {
        matrix[positions1[i][0]][positions1[i][1]] = bits[i];
        matrix[positions2[i][0]][positions2[i][1]] = bits[i];
      }
    }

    // Version info lookup (pre-computed for versions 7-40)
    const VERSION_INFO = {
      7: 0x07C94, 8: 0x085BC, 9: 0x09A99, 10: 0x0A4D3, 11: 0x0BBF6,
      12: 0x0C762, 13: 0x0D847, 14: 0x0E60D, 15: 0x0F928, 16: 0x10B78,
      17: 0x1145D, 18: 0x12A17, 19: 0x13532, 20: 0x149A6, 21: 0x15683,
      22: 0x168C9, 23: 0x177EC, 24: 0x18EC4, 25: 0x191E1, 26: 0x1AFAB,
      27: 0x1B08E, 28: 0x1CC1A, 29: 0x1D33F, 30: 0x1ED75, 31: 0x1F250,
      32: 0x209D5, 33: 0x216F0, 34: 0x228BA, 35: 0x2379F, 36: 0x24B0B,
      37: 0x2542E, 38: 0x26A64, 39: 0x27541, 40: 0x28C69
    };

    function writeVersionInfo(matrix, size, version) {
      if (version < 7) return;
      const info = VERSION_INFO[version] || 0;
      const bits = [];
      for (let i = 17; i >= 0; i--) bits.push((info >> i) & 1);

      let idx = 0;
      for (let i = 0; i < 6; i++) {
        for (let j = 0; j < 3; j++) {
          const bit = bits[idx++];
          matrix[i][size - 11 + j] = bit;
          matrix[size - 11 + j][i] = bit;
        }
      }
    }

    // Render to canvas
    function renderToCanvas(canvas, matrix, moduleSize, margin) {
      const size = matrix.length;
      const canvasSize = size * moduleSize + margin * 2;
      canvas.width = canvasSize;
      canvas.height = canvasSize;

      const ctx = canvas.getContext('2d');
      ctx.fillStyle = '#ffffff';
      ctx.fillRect(0, 0, canvasSize, canvasSize);

      ctx.fillStyle = '#000000';
      for (let r = 0; r < size; r++) {
        for (let c = 0; c < size; c++) {
          if (matrix[r][c] === 1) {
            ctx.fillRect(margin + c * moduleSize, margin + r * moduleSize, moduleSize, moduleSize);
          }
        }
      }
    }

    // Public API
    return {
      generate(text, canvas, moduleSize = 4, margin = 16) {
        const bytes = new TextEncoder().encode(text);
        const versionInfo = selectVersion(bytes.length);
        if (!versionInfo) {
          throw new Error('Data too large for QR code');
        }

        const dataCodewords = createDataCodewords(bytes, versionInfo.dataCapacity);
        const allCodewords = interleave(dataCodewords, versionInfo.eccPerBlock, versionInfo.blocks);
        const matrix = buildMatrix(versionInfo.version, allCodewords);
        renderToCanvas(canvas, matrix, moduleSize, margin);
        return versionInfo.version;
      }
    };
  })();

  // QR Code button handler
  if (els.btnGenerateQr) {
    els.btnGenerateQr.addEventListener('click', () => {
      const token = els.jwtEncoded.value.trim();
      if (!token) {
        showToast('Generate or paste a token first!', true);
        return;
      }

      try {
        const version = QRCode.generate(token, els.qrCanvas, 3, 12);
        els.qrSection.classList.remove('hidden');
        showToast(`QR code generated (Version ${version})`, 'info');
      } catch (e) {
        showToast(`QR generation failed: ${e.message}`, true);
      }
    });
  }

  // ==========================================================================
  // Event Listeners: Standard JWT Panel
  // ==========================================================================

  async function updateEncodedJwtFromEditors() {
    if (isEditingEncoded) return;

    const headerText = els.jwtHeader.value.trim();
    const payloadText = els.jwtPayload.value.trim();
    const alg = els.jwtAlg.value;

    const headerJson = tryParseJson(headerText);
    const payloadJson = tryParseJson(payloadText);

    if (headerJson) {
      els.headerStatus.textContent = '✓ Valid';
      els.headerStatus.className = 'status-indicator success';
    } else {
      els.headerStatus.textContent = '✗ Invalid';
      els.headerStatus.className = 'status-indicator danger';
    }

    if (payloadJson) {
      els.payloadStatus.textContent = '✓ Valid';
      els.payloadStatus.className = 'status-indicator success';
      updateTtlIndicator(payloadJson);
    } else {
      els.payloadStatus.textContent = '✗ Invalid';
      els.payloadStatus.className = 'status-indicator danger';
      els.ttlStatusBar.classList.add('hidden');
    }

    if (!headerJson || !payloadJson) {
      els.jwtEncoded.value = '';
      els.tokenStatus.textContent = '✗ Error parsing JSON';
      els.tokenStatus.className = 'status-badge danger';
      els.visHeader.textContent = '';
      els.visPayload.textContent = '';
      els.visSignature.textContent = '';
      updateTokenSize('');
      renderValidationChecklist(runValidationChecklist(null, null, null));
      return;
    }

    if (headerJson.alg !== alg) {
      headerJson.alg = alg;
      els.jwtHeader.value = JSON.stringify(headerJson, null, 2);
    }

    try {
      let result;
      if (isRsaAlg(alg)) {
        const privatePem = els.rsaPrivateKey.value.trim();
        if (!privatePem) {
          els.jwtEncoded.value = '';
          els.tokenStatus.textContent = 'Paste or generate RSA private key';
          els.tokenStatus.className = 'status-badge warning';
          updateTokenSize('');
          renderValidationChecklist(runValidationChecklist(headerJson, payloadJson, null));
          return;
        }
        result = await signJwtRsa(headerJson, payloadJson, privatePem);
      } else {
        const key = els.jwtKey.value;
        const isHex = els.keyFormatHex.checked;
        const keyFormat = isHex ? 'hex' : 'text';
        result = await signJwtHmac(headerJson, payloadJson, key, keyFormat);
      }

      els.jwtEncoded.value = result.token;
      
      els.visHeader.textContent = result.headerBase64;
      els.visPayload.textContent = result.payloadBase64;
      els.visSignature.textContent = result.signatureBase64;

      els.tokenStatus.textContent = '✓ Signature Verified';
      els.tokenStatus.className = 'status-badge success';

      els.decodedHeaderView.textContent = JSON.stringify(headerJson, null, 2);
      els.decodedPayloadView.textContent = JSON.stringify(payloadJson, null, 2);

      updateTokenSize(result.token);
      renderValidationChecklist(runValidationChecklist(headerJson, payloadJson, true));
    } catch (e) {
      els.jwtEncoded.value = '';
      els.tokenStatus.textContent = `✗ ${e.message}`;
      els.tokenStatus.className = 'status-badge danger';
      els.visHeader.textContent = '';
      els.visPayload.textContent = '';
      els.visSignature.textContent = '';
      updateTokenSize('');
      renderValidationChecklist(runValidationChecklist(headerJson, payloadJson, null));
    }
  }

  async function updateEditorsFromEncodedToken() {
    const token = els.jwtEncoded.value.trim();
    if (!token) {
      els.tokenStatus.textContent = 'Waiting for input...';
      els.tokenStatus.className = 'status-badge';
      els.ttlStatusBar.classList.add('hidden');
      updateTokenSize('');
      renderValidationChecklist(runValidationChecklist(null, null, null));
      return;
    }

    isEditingEncoded = true;

    try {
      // Detect algorithm from header
      const parts = token.split('.');
      if (parts.length !== 3) throw new Error('JWT must have 3 parts');
      const decoder = new TextDecoder();
      const headerObj = JSON.parse(decoder.decode(base64urlDecode(parts[0])));
      const alg = headerObj.alg || 'HS256';

      let result;
      if (isRsaAlg(alg)) {
        const publicPem = els.rsaPublicKey.value.trim();
        if (!publicPem) {
          // Just decode without verifying
          const payloadObj = JSON.parse(decoder.decode(base64urlDecode(parts[1])));
          els.jwtHeader.value = JSON.stringify(headerObj, null, 2);
          els.jwtPayload.value = JSON.stringify(payloadObj, null, 2);
          els.jwtAlg.value = alg;
          syncAlgorithmUI();
          els.visHeader.textContent = parts[0];
          els.visPayload.textContent = parts[1];
          els.visSignature.textContent = parts[2];
          els.tokenStatus.textContent = '⚠ No public key for verification';
          els.tokenStatus.className = 'status-badge warning';
          els.decodedHeaderView.textContent = JSON.stringify(headerObj, null, 2);
          els.decodedPayloadView.textContent = JSON.stringify(payloadObj, null, 2);
          updateTtlIndicator(payloadObj);
          updateTokenSize(token);
          renderValidationChecklist(runValidationChecklist(headerObj, payloadObj, null));
          return;
        }
        result = await verifyJwtRsa(token, publicPem);
      } else {
        const key = els.jwtKey.value;
        const isHex = els.keyFormatHex.checked;
        const keyFormat = isHex ? 'hex' : 'text';
        result = await verifyJwtHmac(token, key, keyFormat);
      }

      els.jwtHeader.value = JSON.stringify(result.headerObj, null, 2);
      els.jwtPayload.value = JSON.stringify(result.payloadObj, null, 2);
      
      els.headerStatus.textContent = '✓ Valid';
      els.headerStatus.className = 'status-indicator success';
      els.payloadStatus.textContent = '✓ Valid';
      els.payloadStatus.className = 'status-indicator success';

      if (result.headerObj.alg) {
        els.jwtAlg.value = result.headerObj.alg;
        syncAlgorithmUI();
      }

      els.visHeader.textContent = result.headerBase64;
      els.visPayload.textContent = result.payloadBase64;
      els.visSignature.textContent = result.signatureBase64;

      if (result.isValid) {
        els.tokenStatus.textContent = '✓ Signature Verified';
        els.tokenStatus.className = 'status-badge success';
      } else {
        els.tokenStatus.textContent = '✗ Invalid Signature';
        els.tokenStatus.className = 'status-badge danger';
      }

      updateTtlIndicator(result.payloadObj);
      updateTokenSize(token);
      els.decodedHeaderView.textContent = JSON.stringify(result.headerObj, null, 2);
      els.decodedPayloadView.textContent = JSON.stringify(result.payloadObj, null, 2);

      renderValidationChecklist(runValidationChecklist(result.headerObj, result.payloadObj, result.isValid));
    } catch (e) {
      els.tokenStatus.textContent = `✗ ${e.message}`;
      els.tokenStatus.className = 'status-badge danger';
      
      els.visHeader.textContent = '';
      els.visPayload.textContent = '';
      els.visSignature.textContent = '';
      els.ttlStatusBar.classList.add('hidden');
      updateTokenSize('');
      renderValidationChecklist(runValidationChecklist(null, null, null));
    } finally {
      isEditingEncoded = false;
    }
  }

  // Bind inputs
  ['input', 'change'].forEach(evt => {
    els.jwtHeader.addEventListener(evt, updateEncodedJwtFromEditors);
    els.jwtPayload.addEventListener(evt, updateEncodedJwtFromEditors);
    els.jwtKey.addEventListener(evt, () => { updateEncodedJwtFromEditors(); renderStrengthAdvisor(); });
  });

  els.jwtAlg.addEventListener('change', () => {
    syncAlgorithmUI();
    updateEncodedJwtFromEditors();
  });

  els.keyFormatText.addEventListener('change', () => { updateEncodedJwtFromEditors(); renderStrengthAdvisor(); });
  els.keyFormatHex.addEventListener('change', () => { updateEncodedJwtFromEditors(); renderStrengthAdvisor(); });
  els.jwtEncoded.addEventListener('input', updateEditorsFromEncodedToken);

  // RSA key change triggers re-sign
  els.rsaPrivateKey.addEventListener('input', updateEncodedJwtFromEditors);
  els.rsaPublicKey.addEventListener('input', updateEncodedJwtFromEditors);

  // Copy standard token
  els.btnCopyToken.addEventListener('click', () => {
    const token = els.jwtEncoded.value;
    if (token) {
      navigator.clipboard.writeText(token);
      showToast('JWT Token copied to clipboard!');
    } else {
      showToast('No token to copy!', true);
    }
  });

  // Tamper Signature Simulator
  els.btnTamperToken.addEventListener('click', () => {
    const token = els.jwtEncoded.value.trim();
    if (!token) {
      showToast('Please generate or paste a token first!', true);
      return;
    }

    const parts = token.split('.');
    if (parts.length !== 3) {
      showToast('Invalid JWT structure!', true);
      return;
    }

    let signature = parts[2];
    if (signature.length === 0) {
      showToast('No signature to tamper!', true);
      return;
    }

    // Mutate the very last character of the signature
    const lastChar = signature.slice(-1);
    let newChar = lastChar === 'A' ? 'B' : 'A';
    if (lastChar.match(/[a-z]/i)) {
      newChar = lastChar === lastChar.toUpperCase() ? lastChar.toLowerCase() : lastChar.toUpperCase();
    }
    
    const tamperedSignature = signature.slice(0, -1) + newChar;
    const tamperedToken = `${parts[0]}.${parts[1]}.${tamperedSignature}`;
    
    els.jwtEncoded.value = tamperedToken;
    showToast('Signature tampered! Simulating audit payload...');
    
    // Trigger validation instantly to show signature validation failure
    updateEditorsFromEncodedToken();
  });

  // Load Payload Template
  els.claimsTemplate.addEventListener('change', () => {
    const templateKey = els.claimsTemplate.value;
    if (TEMPLATES[templateKey]) {
      const tpl = JSON.parse(JSON.stringify(TEMPLATES[templateKey]));
      if (templateKey !== 'clear') {
        const now = Math.floor(Date.now() / 1000);
        tpl.iat = now;
        if (templateKey === 'session') tpl.exp = now + 3600;
        if (templateKey === 'oauth') tpl.exp = now + 86400;
        if (templateKey === 'micro') tpl.exp = now + 604800;
      }
      els.jwtPayload.value = JSON.stringify(tpl, null, 2);
      updateEncodedJwtFromEditors();
      showToast(`Loaded payload template: ${els.claimsTemplate.options[els.claimsTemplate.selectedIndex].text}`);
    }
  });

  // Helper to adjust timestamp inside the payload JSON editor
  function updatePayloadTimestamps(updaterFn) {
    const txt = els.jwtPayload.value.trim();
    let payload = tryParseJson(txt);
    if (!payload) {
      showToast('Fix JSON payload syntax first!', true);
      return;
    }
    payload = updaterFn(payload);
    els.jwtPayload.value = JSON.stringify(payload, null, 2);
    updateEncodedJwtFromEditors();
  }

  // Time buttons click events
  els.btnTimeNow.addEventListener('click', () => {
    updatePayloadTimestamps(payload => {
      payload.iat = Math.floor(Date.now() / 1000);
      showToast('Set iat to current time.');
      return payload;
    });
  });

  function setExpOffset(offsetSec, desc) {
    updatePayloadTimestamps(payload => {
      const baseTime = payload.iat || Math.floor(Date.now() / 1000);
      payload.exp = baseTime + offsetSec;
      showToast(`Set exp to ${desc} from iat.`);
      return payload;
    });
  }

  els.btnTime1h.addEventListener('click', () => setExpOffset(3600, '+1 hour'));
  els.btnTime1d.addEventListener('click', () => setExpOffset(86400, '+1 day'));
  els.btnTime7d.addEventListener('click', () => setExpOffset(604800, '+7 days'));

  // Redirect token to Encryptor panel
  els.btnSendToEncryptor.addEventListener('click', () => {
    const token = els.jwtEncoded.value;
    if (token) {
      els.encPlaintext.value = token;
      els.encKey.value = els.jwtKey.value;
      if (els.keyFormatHex.checked) {
        els.encKeyFormatHex.checked = true;
      } else {
        els.encKeyFormatText.checked = true;
      }
      switchPanel('panel-encrypted', els.tabBtnEncrypted);
      showToast('Token copied into Encryptor!');
    } else {
      showToast('Generate a token first!', true);
    }
  });

  // ==========================================================================
  // RSA Key Generation (Standard panel inline button)
  // ==========================================================================
  els.btnGenerateRsa.addEventListener('click', async () => {
    els.btnGenerateRsa.disabled = true;
    els.btnGenerateRsa.textContent = 'Generating...';
    try {
      const keys = await generateRsaKeyPair();
      els.rsaPrivateKey.value = keys.privatePem;
      els.rsaPublicKey.value = keys.publicPem;
      showToast('RSA-2048 key pair generated!');
      updateEncodedJwtFromEditors();
    } catch (e) {
      showToast(`RSA generation failed: ${e.message}`, true);
    } finally {
      els.btnGenerateRsa.disabled = false;
      els.btnGenerateRsa.innerHTML = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg> Generate Keypair`;
    }
  });

  // ==========================================================================
  // Event Listeners: Encrypted Token Panel
  // ==========================================================================

  els.btnEncrypt.addEventListener('click', async () => {
    const plaintext = els.encPlaintext.value;
    const key = els.encKey.value;
    const isHex = els.encKeyFormatHex.checked;
    const derive = els.encKeyDerive.checked;
    const customIv = els.encCustomIv.value.trim();

    if (!plaintext) {
      showToast('Please enter plaintext to encrypt', true);
      return;
    }
    if (!key) {
      showToast('Please enter an encryption key', true);
      return;
    }

    try {
      const keyFormat = isHex ? 'hex' : 'text';
      const result = await encryptGcm(plaintext, key, keyFormat, derive, customIv);
      els.encCiphertext.value = result;
      showToast('Payload encrypted successfully!');
    } catch (e) {
      showToast(`Encryption failed: ${e.message}`, true);
      els.encCiphertext.value = '';
    }
  });

  els.btnCopyEncToken.addEventListener('click', () => {
    const token = els.encCiphertext.value;
    if (token) {
      navigator.clipboard.writeText(token);
      showToast('Encrypted token copied to clipboard!');
    } else {
      showToast('Nothing to copy!', true);
    }
  });

  els.btnDecrypt.addEventListener('click', async () => {
    const tokenStr = els.decToken.value.trim();
    const key = els.decKey.value;
    const isHex = els.decKeyFormatHex.checked;
    const derive = els.decKeyDerive.checked;

    if (!tokenStr) {
      showToast('Please paste an encrypted token to decrypt', true);
      return;
    }
    if (!key) {
      showToast('Please enter a decryption key', true);
      return;
    }

    try {
      const keyFormat = isHex ? 'hex' : 'text';
      const result = await decryptGcm(tokenStr, key, keyFormat, derive);
      
      els.decPlaintext.value = result.plaintext;
      els.decStatusBadge.textContent = '✓ Success';
      els.decStatusBadge.className = 'status-badge success';
      
      els.analysisIvHex.textContent = result.ivHex;
      els.analysisCipherHex.textContent = result.ciphertextHex.substring(0, 100) + (result.ciphertextHex.length > 100 ? '...' : '');
      els.analysisCipherMeta.textContent = `${result.ciphertextLength} bytes (${result.ciphertextHex.length} hex characters)`;
      els.analysisTagHex.textContent = result.tagHex;

      els.decResultSection.classList.remove('hidden');
      showToast('Decryption successful!');
    } catch (e) {
      els.decPlaintext.value = '';
      els.decStatusBadge.textContent = '✗ Failed';
      els.decStatusBadge.className = 'status-badge danger';
      els.decResultSection.classList.remove('hidden');
      
      els.analysisIvHex.textContent = '—';
      els.analysisCipherHex.textContent = '—';
      els.analysisCipherMeta.textContent = '';
      els.analysisTagHex.textContent = '—';

      showToast(`Decryption failed: Check key and token format.`, true);
    }
  });

  els.btnCopyDecPlaintext.addEventListener('click', () => {
    const txt = els.decPlaintext.value;
    if (txt) {
      navigator.clipboard.writeText(txt);
      showToast('Decrypted plaintext copied!');
    }
  });

  els.btnSendToDecoder.addEventListener('click', () => {
    const txt = els.decPlaintext.value.trim();
    if (txt) {
      els.jwtEncoded.value = txt;
      els.jwtKey.value = els.decKey.value;
      if (els.decKeyFormatHex.checked) {
        els.keyFormatHex.checked = true;
      } else {
        els.keyFormatText.checked = true;
      }
      switchPanel('panel-standard', els.tabBtnStandard);
      updateEditorsFromEncodedToken();
      showToast('Sent to JWT Decoder!');
    }
  });

  // ==========================================================================
  // Event Listeners: Utilities Panel
  // ==========================================================================

  els.btnGenerateRandomKey.addEventListener('click', () => {
    const size = parseInt(els.genKeySize.value, 10);
    const format = els.genKeyFormat.value;

    const randomBytes = crypto.getRandomValues(new Uint8Array(size));
    let result = '';

    if (format === 'hex') {
      result = bufToHex(randomBytes);
    } else if (format === 'base64') {
      result = btoa(String.fromCharCode.apply(null, randomBytes));
    } else if (format === 'base64url') {
      result = base64urlEncode(randomBytes.buffer);
    }

    els.generatedOutputKey.value = result;
    showToast('Secure random key generated!');
  });

  els.btnCopyGenKey.addEventListener('click', () => {
    const val = els.generatedOutputKey.value;
    if (val) {
      navigator.clipboard.writeText(val);
      showToast('Copied to clipboard!');
    }
  });

  // RSA Keypair Generator (Utilities panel)
  els.btnGenerateRsaUtility.addEventListener('click', async () => {
    els.btnGenerateRsaUtility.disabled = true;
    els.btnGenerateRsaUtility.textContent = 'Generating RSA-2048...';
    try {
      const keys = await generateRsaKeyPair();
      els.rsaGenPrivate.value = keys.privatePem;
      els.rsaGenPublic.value = keys.publicPem;
      showToast('RSA-2048 key pair generated!');
    } catch (e) {
      showToast(`RSA generation failed: ${e.message}`, true);
    } finally {
      els.btnGenerateRsaUtility.disabled = false;
      els.btnGenerateRsaUtility.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg> Generate RSA-2048 Keypair`;
    }
  });

  els.btnCopyRsaPrivate.addEventListener('click', () => {
    const val = els.rsaGenPrivate.value;
    if (val) { navigator.clipboard.writeText(val); showToast('Private key copied!'); }
  });

  els.btnCopyRsaPublic.addEventListener('click', () => {
    const val = els.rsaGenPublic.value;
    if (val) { navigator.clipboard.writeText(val); showToast('Public key copied!'); }
  });

  els.btnUseRsaKeys.addEventListener('click', () => {
    const priv = els.rsaGenPrivate.value.trim();
    const pub = els.rsaGenPublic.value.trim();
    if (!priv || !pub) {
      showToast('Generate a key pair first!', true);
      return;
    }
    els.jwtAlg.value = 'RS256';
    syncAlgorithmUI();
    els.rsaPrivateKey.value = priv;
    els.rsaPublicKey.value = pub;
    switchPanel('panel-standard', els.tabBtnStandard);
    updateEncodedJwtFromEditors();
    showToast('RSA keys loaded into JWT Signer!');
  });

  // Key Deriver
  async function updateKeyDerivation() {
    const val = els.deriveInputText.value;
    if (!val) {
      els.derivedHexOutput.value = '';
      els.derivedBase64Output.value = '';
      return;
    }
    const hash = await sha256(val);
    els.derivedHexOutput.value = bufToHex(hash);
    els.derivedBase64Output.value = btoa(String.fromCharCode.apply(null, hash));
  }

  els.deriveInputText.addEventListener('input', updateKeyDerivation);

  els.btnCopyDerivedHex.addEventListener('click', () => {
    const val = els.derivedHexOutput.value;
    if (val) {
      navigator.clipboard.writeText(val);
      showToast('Copied derived hex!');
    }
  });

  els.btnCopyDerivedBase64.addEventListener('click', () => {
    const val = els.derivedBase64Output.value;
    if (val) {
      navigator.clipboard.writeText(val);
      showToast('Copied derived Base64!');
    }
  });

  // ==========================================================================
  // Universal Encoding Converter
  // ==========================================================================

  function inputToBytes(input, format) {
    switch (format) {
      case 'text':
        return new TextEncoder().encode(input);
      case 'hex': {
        const cleaned = input.replace(/\s+/g, '');
        if (cleaned.length % 2 !== 0) throw new Error('Hex string must have even length');
        return hexToBuf(cleaned);
      }
      case 'base64': {
        try {
          const binary = atob(input.trim());
          const bytes = new Uint8Array(binary.length);
          for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
          return bytes;
        } catch (e) {
          throw new Error('Invalid Base64 input');
        }
      }
      case 'base64url': {
        try {
          let b64 = input.trim().replace(/-/g, '+').replace(/_/g, '/');
          while (b64.length % 4) b64 += '=';
          const binary = atob(b64);
          const bytes = new Uint8Array(binary.length);
          for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
          return bytes;
        } catch (e) {
          throw new Error('Invalid Base64URL input');
        }
      }
      default:
        throw new Error('Unknown format');
    }
  }

  function bytesToOutputs(bytes) {
    const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
    const hex = bufToHex(bytes);
    const b64 = btoa(String.fromCharCode.apply(null, bytes));
    const b64url = base64urlEncode(bytes.buffer);
    return { text, hex, base64: b64, base64url: b64url };
  }

  els.btnConvert.addEventListener('click', () => {
    const input = els.convInput.value;
    const format = els.convInputFormat.value;

    if (!input) {
      showToast('Enter some data to convert!', true);
      return;
    }

    try {
      const bytes = inputToBytes(input, format);
      const outputs = bytesToOutputs(bytes);

      els.convOutText.value = outputs.text;
      els.convOutHex.value = outputs.hex;
      els.convOutBase64.value = outputs.base64;
      els.convOutBase64url.value = outputs.base64url;

      showToast('Conversion complete!');
    } catch (e) {
      showToast(`Conversion error: ${e.message}`, true);
    }
  });

  // Converter copy buttons
  els.btnCopyConvText.addEventListener('click', () => {
    const val = els.convOutText.value;
    if (val) { navigator.clipboard.writeText(val); showToast('Text copied!'); }
  });
  els.btnCopyConvHex.addEventListener('click', () => {
    const val = els.convOutHex.value;
    if (val) { navigator.clipboard.writeText(val); showToast('Hex copied!'); }
  });
  els.btnCopyConvBase64.addEventListener('click', () => {
    const val = els.convOutBase64.value;
    if (val) { navigator.clipboard.writeText(val); showToast('Base64 copied!'); }
  });
  els.btnCopyConvBase64url.addEventListener('click', () => {
    const val = els.convOutBase64url.value;
    if (val) { navigator.clipboard.writeText(val); showToast('Base64URL copied!'); }
  });

  // ==========================================================================
  // Hash Generator
  // ==========================================================================

  function switchHashMode(mode) {
    currentHashMode = mode;

    // Toggle mode buttons
    document.querySelectorAll('.hash-mode-btn').forEach(btn => {
      btn.classList.toggle('active', btn.getAttribute('data-mode') === mode);
    });

    // Show/hide groups
    if (els.hashTextGroup) els.hashTextGroup.classList.toggle('hidden', mode === 'file');
    if (els.hashHmacGroup) els.hashHmacGroup.classList.toggle('hidden', mode !== 'hmac');
    if (els.hashFileGroup) els.hashFileGroup.classList.toggle('hidden', mode !== 'file');
  }

  if (els.hashModeText) {
    els.hashModeText.addEventListener('click', () => switchHashMode('text'));
  }
  if (els.hashModeHmac) {
    els.hashModeHmac.addEventListener('click', () => switchHashMode('hmac'));
  }
  if (els.hashModeFile) {
    els.hashModeFile.addEventListener('click', () => switchHashMode('file'));
  }

  // File drop zone
  if (els.hashFileDrop) {
    els.hashFileDrop.addEventListener('click', () => {
      if (els.hashFileInput) els.hashFileInput.click();
    });

    els.hashFileDrop.addEventListener('dragover', (e) => {
      e.preventDefault();
      els.hashFileDrop.classList.add('dragover');
    });

    els.hashFileDrop.addEventListener('dragleave', () => {
      els.hashFileDrop.classList.remove('dragover');
    });

    els.hashFileDrop.addEventListener('drop', (e) => {
      e.preventDefault();
      els.hashFileDrop.classList.remove('dragover');
      if (e.dataTransfer.files.length > 0) {
        selectedHashFile = e.dataTransfer.files[0];
        els.hashFileInfo.textContent = `Selected: ${selectedHashFile.name} (${formatFileSize(selectedHashFile.size)})`;
      }
    });
  }

  if (els.hashFileInput) {
    els.hashFileInput.addEventListener('change', () => {
      if (els.hashFileInput.files.length > 0) {
        selectedHashFile = els.hashFileInput.files[0];
        els.hashFileInfo.textContent = `Selected: ${selectedHashFile.name} (${formatFileSize(selectedHashFile.size)})`;
      }
    });
  }

  function formatFileSize(bytes) {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  }

  async function computeHash(data, algorithm) {
    const hashBuffer = await crypto.subtle.digest(algorithm, data);
    return bufToHex(new Uint8Array(hashBuffer));
  }

  async function computeHmacHash(data, key, algorithm) {
    const keyBytes = new TextEncoder().encode(key);
    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      keyBytes,
      { name: "HMAC", hash: { name: algorithm } },
      false,
      ["sign"]
    );
    const sigBuffer = await crypto.subtle.sign("HMAC", cryptoKey, data);
    return bufToHex(new Uint8Array(sigBuffer));
  }

  if (els.btnHashCompute) {
    els.btnHashCompute.addEventListener('click', async () => {
      try {
        let dataBytes;

        if (currentHashMode === 'file') {
          if (!selectedHashFile) {
            showToast('Please select a file first!', true);
            return;
          }
          const arrayBuffer = await selectedHashFile.arrayBuffer();
          dataBytes = new Uint8Array(arrayBuffer);
        } else {
          const inputText = els.hashInput.value;
          if (!inputText) {
            showToast('Enter text to hash!', true);
            return;
          }
          dataBytes = new TextEncoder().encode(inputText);
        }

        if (currentHashMode === 'hmac') {
          const hmacKey = els.hashHmacKey.value;
          if (!hmacKey) {
            showToast('Enter an HMAC key!', true);
            return;
          }
          const [h256, h384, h512] = await Promise.all([
            computeHmacHash(dataBytes, hmacKey, 'SHA-256'),
            computeHmacHash(dataBytes, hmacKey, 'SHA-384'),
            computeHmacHash(dataBytes, hmacKey, 'SHA-512')
          ]);
          els.hashSha256.textContent = h256;
          els.hashSha384.textContent = h384;
          els.hashSha512.textContent = h512;
        } else {
          const [h256, h384, h512] = await Promise.all([
            computeHash(dataBytes, 'SHA-256'),
            computeHash(dataBytes, 'SHA-384'),
            computeHash(dataBytes, 'SHA-512')
          ]);
          els.hashSha256.textContent = h256;
          els.hashSha384.textContent = h384;
          els.hashSha512.textContent = h512;
        }

        showToast(`${currentHashMode === 'hmac' ? 'HMAC' : currentHashMode === 'file' ? 'File' : 'Text'} hash computed!`);
      } catch (e) {
        showToast(`Hash error: ${e.message}`, true);
      }
    });
  }

  // Hash copy buttons
  if (els.btnCopySha256) {
    els.btnCopySha256.addEventListener('click', () => {
      const val = els.hashSha256.textContent;
      if (val && val !== '—') { navigator.clipboard.writeText(val); showToast('SHA-256 copied!'); }
    });
  }
  if (els.btnCopySha384) {
    els.btnCopySha384.addEventListener('click', () => {
      const val = els.hashSha384.textContent;
      if (val && val !== '—') { navigator.clipboard.writeText(val); showToast('SHA-384 copied!'); }
    });
  }
  if (els.btnCopySha512) {
    els.btnCopySha512.addEventListener('click', () => {
      const val = els.hashSha512.textContent;
      if (val && val !== '—') { navigator.clipboard.writeText(val); showToast('SHA-512 copied!'); }
    });
  }

  // ==========================================================================
  // Password Generator
  // ==========================================================================

  const CHARSETS = {
    upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    lower: 'abcdefghijklmnopqrstuvwxyz',
    digits: '0123456789',
    symbols: '!@#$%^&*()_+-=[]{}|;:,.<>?'
  };

  function getPasswordCharPool() {
    let pool = '';
    if (els.pwUpper && els.pwUpper.checked) pool += CHARSETS.upper;
    if (els.pwLower && els.pwLower.checked) pool += CHARSETS.lower;
    if (els.pwDigits && els.pwDigits.checked) pool += CHARSETS.digits;
    if (els.pwSymbols && els.pwSymbols.checked) pool += CHARSETS.symbols;
    return pool;
  }

  function generatePassword(length, pool) {
    if (!pool) return '';
    const randomValues = crypto.getRandomValues(new Uint32Array(length));
    let password = '';
    for (let i = 0; i < length; i++) {
      password += pool[randomValues[i] % pool.length];
    }
    return password;
  }

  function calculateEntropy(length, poolSize) {
    if (poolSize <= 0 || length <= 0) return 0;
    return Math.round(length * Math.log2(poolSize));
  }

  function getEntropyLevel(bits) {
    if (bits >= 128) return { label: 'Excellent', level: 'excellent', percent: 100 };
    if (bits >= 80) return { label: 'Strong', level: 'high', percent: 80 };
    if (bits >= 60) return { label: 'Moderate', level: 'medium', percent: 60 };
    if (bits >= 40) return { label: 'Weak', level: 'low', percent: 40 };
    return { label: 'Very Weak', level: 'low', percent: 20 };
  }

  function updateEntropyMeter() {
    const pool = getPasswordCharPool();
    const length = els.pwLength ? parseInt(els.pwLength.value, 10) : 24;
    const bits = calculateEntropy(length, pool.length);
    const info = getEntropyLevel(bits);

    if (els.entropyBits) els.entropyBits.textContent = `${bits} bits — ${info.label}`;
    if (els.entropyFill) {
      els.entropyFill.style.width = `${info.percent}%`;
      els.entropyFill.className = `entropy-fill ${info.level}`;
    }
  }

  // Length slider
  if (els.pwLength) {
    els.pwLength.addEventListener('input', () => {
      if (els.pwLengthValue) els.pwLengthValue.textContent = els.pwLength.value;
      updateEntropyMeter();
    });
  }

  // Charset checkboxes
  [els.pwUpper, els.pwLower, els.pwDigits, els.pwSymbols].forEach(cb => {
    if (cb) cb.addEventListener('change', updateEntropyMeter);
  });

  // Generate passwords button
  if (els.btnGeneratePasswords) {
    els.btnGeneratePasswords.addEventListener('click', () => {
      const pool = getPasswordCharPool();
      if (!pool) {
        showToast('Select at least one character set!', true);
        return;
      }

      const length = els.pwLength ? parseInt(els.pwLength.value, 10) : 24;
      const batchCount = els.pwBatchCount ? Math.min(20, Math.max(1, parseInt(els.pwBatchCount.value, 10) || 5)) : 5;

      const passwords = [];
      for (let i = 0; i < batchCount; i++) {
        passwords.push(generatePassword(length, pool));
      }

      // Update entropy
      updateEntropyMeter();

      // Render password list
      if (els.pwOutputList) {
        els.pwOutputList.innerHTML = '';
        passwords.forEach((pw, idx) => {
          const item = document.createElement('div');
          item.className = 'password-item';

          const val = document.createElement('span');
          val.className = 'pw-text';
          val.textContent = pw;

          const copyBtn = document.createElement('button');
          copyBtn.type = 'button';
          copyBtn.className = 'pw-copy-btn';
          copyBtn.textContent = 'Copy';
          copyBtn.addEventListener('click', () => {
            navigator.clipboard.writeText(pw);
            showToast(`Password #${idx + 1} copied!`);
          });

          item.appendChild(val);
          item.appendChild(copyBtn);
          els.pwOutputList.appendChild(item);
        });
      }

      showToast(`Generated ${batchCount} password${batchCount > 1 ? 's' : ''}!`);
    });
  }

  // ==========================================================================
  // Keyboard Shortcuts
  // ==========================================================================

  document.addEventListener('keydown', (e) => {
    // Ctrl+Enter → Encode / re-sign JWT
    if (e.ctrlKey && e.key === 'Enter') {
      e.preventDefault();
      updateEncodedJwtFromEditors();
      showToast('Token re-encoded!', 'info');
    }

    // Ctrl+Shift+C → Copy token
    if (e.ctrlKey && e.shiftKey && (e.key === 'C' || e.key === 'c')) {
      e.preventDefault();
      const token = els.jwtEncoded.value;
      if (token) {
        navigator.clipboard.writeText(token);
        showToast('Token copied to clipboard!');
      } else {
        showToast('No token to copy!', true);
      }
    }
  });

  // ==========================================================================
  // Initialization
  // ==========================================================================

  initTheme();
  initStandardPanel();
  updateKeyDerivation();
  renderStrengthAdvisor();
  updateEntropyMeter();

  // Position indicator after layout settles
  requestAnimationFrame(() => {
    moveIndicator(els.tabBtnStandard);
  });

})();
