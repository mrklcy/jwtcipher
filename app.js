/**
 * JWT Cipher — Core Cryptographic & Application Logic (v3.0)
 * Powered entirely by the Browser's native Web Crypto API.
 *
 * New in v3.0:
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
    tabBtnStandard: $('tab-btn-standard'),
    tabBtnEncrypted: $('tab-btn-encrypted'),
    tabBtnUtilities: $('tab-btn-utilities'),
    tabBtnConverter: $('tab-btn-converter'),
    panelStandard: $('panel-standard'),
    panelEncrypted: $('panel-encrypted'),
    panelUtilities: $('panel-utilities'),
    panelConverter: $('panel-converter'),

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

    // Global
    toastContainer: $('toast-container')
  };

  // State
  let isEditingEncoded = false;

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

  function showToast(message, isError = false) {
    const toast = document.createElement('div');
    toast.className = 'toast';
    if (isError) toast.style.borderLeftColor = 'var(--color-danger)';
    toast.textContent = message;
    
    els.toastContainer.appendChild(toast);
    
    setTimeout(() => {
      toast.classList.add('leaving');
      toast.addEventListener('animationend', () => toast.remove());
    }, 2800);
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
  // Panel Initialization & Navigation
  // ==========================================================================

  function initStandardPanel() {
    els.jwtHeader.value = JSON.stringify(defaultHeader, null, 2);
    // Load default template (session)
    els.jwtPayload.value = JSON.stringify(TEMPLATES.session, null, 2);
    
    syncAlgorithmUI();
    updateEncodedJwtFromEditors();
  }

  function switchPanel(panelId, activeTabBtn) {
    const panels = [els.panelStandard, els.panelEncrypted, els.panelUtilities, els.panelConverter];
    const tabBtns = [els.tabBtnStandard, els.tabBtnEncrypted, els.tabBtnUtilities, els.tabBtnConverter];

    tabBtns.forEach(btn => {
      btn.classList.remove('active');
      btn.setAttribute('aria-selected', 'false');
    });
    activeTabBtn.classList.add('active');
    activeTabBtn.setAttribute('aria-selected', 'true');

    panels.forEach(panel => {
      if (panel.id === panelId) {
        panel.style.display = 'block';
        panel.classList.add('active');
      } else {
        panel.style.display = 'none';
        panel.classList.remove('active');
      }
    });
  }

  els.tabBtnStandard.addEventListener('click', () => switchPanel('panel-standard', els.tabBtnStandard));
  els.tabBtnEncrypted.addEventListener('click', () => switchPanel('panel-encrypted', els.tabBtnEncrypted));
  els.tabBtnUtilities.addEventListener('click', () => switchPanel('panel-utilities', els.tabBtnUtilities));
  els.tabBtnConverter.addEventListener('click', () => switchPanel('panel-converter', els.tabBtnConverter));

  function setupKeyVisibilityToggle(btn, input) {
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

      renderValidationChecklist(runValidationChecklist(headerJson, payloadJson, true));
    } catch (e) {
      els.jwtEncoded.value = '';
      els.tokenStatus.textContent = `✗ ${e.message}`;
      els.tokenStatus.className = 'status-badge danger';
      els.visHeader.textContent = '';
      els.visPayload.textContent = '';
      els.visSignature.textContent = '';
      renderValidationChecklist(runValidationChecklist(headerJson, payloadJson, null));
    }
  }

  async function updateEditorsFromEncodedToken() {
    const token = els.jwtEncoded.value.trim();
    if (!token) {
      els.tokenStatus.textContent = 'Waiting for input...';
      els.tokenStatus.className = 'status-badge';
      els.ttlStatusBar.classList.add('hidden');
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
  // Initialization
  // ==========================================================================
  initStandardPanel();
  updateKeyDerivation();
  renderStrengthAdvisor();

})();
