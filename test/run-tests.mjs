/**
 * AI Phishing Shield — Unit Test Suite
 * ═══════════════════════════════════════════════════════════════════════════
 * Running: node test/run-tests.mjs
 */

import { extractFeatures } from '../extension/ml/features.js';
import { runInference, isTrustedHost } from '../extension/ml/model.js';

let testsRun = 0;
let testsFailed = 0;

function assert(condition, message) {
  testsRun++;
  if (condition) {
    console.log(`  ✅ PASS: ${message}`);
  } else {
    testsFailed++;
    console.error(`  ❌ FAIL: ${message}`);
  }
}

function group(name, fn) {
  console.log(`\n🏃 Running Group: ${name}`);
  console.log('═'.repeat(name.length + 18));
  try {
    fn();
  } catch (err) {
    testsFailed++;
    console.error(`💥 Group crashed with exception:`, err);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// TEST GROUP 1: URL parsing & scheme checking
// ─────────────────────────────────────────────────────────────────────────────
group('URL Parsing & Safe Extraction', () => {
  const f1 = extractFeatures('https://www.google.com/login');
  assert(f1.hostname === 'google.com', `Extracts clean hostname: "${f1.hostname}"`);
  assert(f1.protocol === 'https:', `Extracts correct protocol: "${f1.protocol}"`);
  assert(f1.hasHttps === true, 'Identifies HTTPS is present');

  const f2 = extractFeatures('http://192.168.1.1/admin');
  assert(f2.hostname === '192.168.1.1', `Extracts IP address hostname: "${f2.hostname}"`);
  assert(f2.hasIpAddress === true, 'Identifies raw IPv4 hostname');
  assert(f2.hasHttps === false, 'Identifies HTTPS is missing');

  const f3 = extractFeatures('file:///D:/STUFF/test.html');
  assert(f3.protocol === 'file:', `Extracts file scheme without mangling: "${f3.protocol}"`);
});

// ─────────────────────────────────────────────────────────────────────────────
// TEST GROUP 2: Feature extraction vectors (42 features)
// ─────────────────────────────────────────────────────────────────────────────
group('Feature Extractor Vector Integrity', () => {
  const f = extractFeatures('https://paypal.com.phishing-verify-secure.net/login?token=123');
  
  assert(f.vector instanceof Float32Array, 'Feature vector is a Float32Array');
  assert(f.vector.length === 42, `Feature vector has exactly 42 inputs (found: ${f.vector.length})`);
  
  // Verify specific feature spots
  // [F04] hasIp (0)
  assert(f.vector[3] === 0, 'F04 (IP address check) is 0 for named domain');
  // [F05] noHttps (0)
  assert(f.vector[4] === 0, 'F05 (Missing HTTPS check) is 0 for https://');
  
  // [F17] suspKeyword (1)
  assert(f.vector[16] === 1, 'F17 (Suspicious keywords in domain) is 1 due to "login" / "secure"');
});

// ─────────────────────────────────────────────────────────────────────────────
// TEST GROUP 3: Trusted domain checks
// ─────────────────────────────────────────────────────────────────────────────
group('Trusted Domains & Academic Whitelist', () => {
  assert(isTrustedHost('google.com') === true, 'google.com is classified as trusted');
  assert(isTrustedHost('www.google.com') === true, 'www.google.com resolves as trusted');
  assert(isTrustedHost('mail.google.com') === true, 'Subdomain mail.google.com is trusted');
  assert(isTrustedHost('overleaf.com') === true, 'overleaf.com is whitelisted');
  
  // Academic & Gov TLDs
  assert(isTrustedHost('mit.edu') === true, 'MIT (.edu) is trusted by TLD');
  assert(isTrustedHost('iitb.ac.in') === true, 'IIT Bombay (.ac.in) is trusted by two-part TLD');
  assert(isTrustedHost('india.gov.in') === true, 'Official Gov portal (.gov.in) is trusted');

  // Negative tests (Phishing look-alikes)
  assert(isTrustedHost('google-login.com') === false, 'Spoof domain google-login.com is NOT trusted');
  assert(isTrustedHost('paypal.com.secure.net') === false, 'Multi-TLD Paypal spoof is NOT trusted');
});

// ─────────────────────────────────────────────────────────────────────────────
// TEST GROUP 4: Scorer Calibration (Safe vs Phishing)
// ─────────────────────────────────────────────────────────────────────────────
group('Scorer Calibration & Risk Thresholds', async () => {
  // Test 1: Trusted site
  const resSafe = await runInference('https://www.overleaf.com/project');
  assert(resSafe.score <= 10, `Trusted site (Overleaf) gets capped safe score: ${resSafe.score}/100`);
  assert(resSafe.level === 'SAFE', `Overleaf risk level is: ${resSafe.level}`);
  assert(resSafe.flags.length === 0, 'No threat explanation flags displayed for trusted site');

  // Test 2: Standard safe site (not on whitelist, but completely clean)
  const resNormal = await runInference('https://example.com/page');
  assert(resNormal.score <= 30, `Clean site (example.com) stays below Warning Threshold: ${resNormal.score}/100`);
  assert(resNormal.level === 'SAFE', `Clean site risk level is: ${resNormal.level}`);

  // Test 3: Highly suspicious phishing site
  const resPhish = await runInference('http://192.168.1.155/login?user=admin@paypal.com&pass=123');
  assert(resPhish.score >= 61, `High-risk site (IP, no HTTPS, @ symbol, login keyword) gets blocked score: ${resPhish.score}/100`);
  assert(resPhish.level === 'DANGEROUS' || resPhish.level === 'CRITICAL', `Phishing site level is: ${resPhish.level}`);
  assert(resPhish.flags.length >= 3, `Phishing site shows descriptive XAI flags (found: ${resPhish.flags.length} flags)`);
});

// ─────────────────────────────────────────────────────────────────────────────
// RESULTS SUMMARY
// ─────────────────────────────────────────────────────────────────────────────
console.log('\n📊 Test Execution Summary');
console.log('═'.repeat(24));
console.log(`Total assertions run : ${testsRun}`);
if (testsFailed === 0) {
  console.log(`🎉 ALL TESTS PASSED SUCCESSFULLY!`);
  process.exit(0);
} else {
  console.error(`🚨 ${testsFailed} TEST(S) FAILED!`);
  process.exit(1);
}
