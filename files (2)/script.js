/* =========================================================
   CipherBench — script.js
   All cryptography happens client-side via CryptoJS. No
   network calls, no storage of the password anywhere.
   ========================================================= */

// ---- Cryptographic configuration ----------------------------------------
// These constants control the strength of the key derivation and cipher.
// Sizes below are expressed the way CryptoJS expects: "words" of 32 bits.
const PBKDF2_ITERATIONS = 100000;      // Strong iteration count to slow brute-force attacks
const KEY_SIZE_WORDS     = 256 / 32;   // 256-bit AES key
const SALT_SIZE_BYTES    = 16;         // 128-bit salt (recommended minimum for PBKDF2)
const IV_SIZE_BYTES      = 16;         // AES block size is always 128 bits -> 16-byte IV

// ---- DOM references -------------------------------------------------------
const passwordInput     = document.getElementById('password');
const togglePasswordBtn = document.getElementById('togglePassword');
const passwordError     = document.getElementById('passwordError');

const plainTextArea   = document.getElementById('plainText');
const plainTextError  = document.getElementById('plainTextError');
const encryptBtn      = document.getElementById('encryptBtn');
const clearEncryptBtn = document.getElementById('clearEncrypt');
const encryptedOutput = document.getElementById('encryptedOutput');
const copyEncryptedBtn = document.getElementById('copyEncrypted');

const cipherInput      = document.getElementById('cipherInput');
const cipherInputError = document.getElementById('cipherInputError');
const decryptBtn       = document.getElementById('decryptBtn');
const clearDecryptBtn  = document.getElementById('clearDecrypt');
const decryptedOutput  = document.getElementById('decryptedOutput');
const copyDecryptedBtn = document.getElementById('copyDecrypted');

const statusBar = document.getElementById('statusBar');

// ---- Small UI helpers -------------------------------------------------------

/** Show a transient status message at the bottom of the console grid. */
function setStatus(message, type) {
  statusBar.textContent = message || '';
  statusBar.classList.remove('is-success', 'is-error');
  if (type === 'success') statusBar.classList.add('is-success');
  if (type === 'error') statusBar.classList.add('is-error');
}

/** Show/clear a field-level validation message. */
function setFieldError(el, message) {
  el.textContent = message || '';
}

function clearAllErrors() {
  setFieldError(passwordError, '');
  setFieldError(plainTextError, '');
  setFieldError(cipherInputError, '');
  setStatus('', null);
}

// ---- Password visibility toggle -------------------------------------------
togglePasswordBtn.addEventListener('click', () => {
  const isHidden = passwordInput.type === 'password';
  passwordInput.type = isHidden ? 'text' : 'password';
  togglePasswordBtn.setAttribute('aria-pressed', String(isHidden));
  togglePasswordBtn.setAttribute('aria-label', isHidden ? 'Hide password' : 'Show password');
});

// ---- Core cryptographic functions -----------------------------------------

/**
 * Derive a 256-bit AES key from a human password using PBKDF2.
 * PBKDF2 repeatedly hashes the password + salt (100,000 rounds here),
 * which makes each individual guess expensive for an attacker running
 * a brute-force or dictionary attack against a stolen ciphertext.
 */
function deriveKey(password, salt) {
  return CryptoJS.PBKDF2(password, salt, {
    keySize: KEY_SIZE_WORDS,
    iterations: PBKDF2_ITERATIONS,
    hasher: CryptoJS.algo.SHA256
  });
}

/**
 * Encrypt plaintext with AES-256-CBC using a password.
 * A brand-new random salt AND a brand-new random IV are generated on
 * every call. Because the derived key depends on the salt, and the
 * cipher's first block depends on the IV, encrypting the exact same
 * text with the exact same password twice will never produce the same
 * ciphertext twice — this is intentional and expected of secure AES use.
 *
 * The output is a single Base64 string with the layout:
 *   [ 16 bytes salt ][ 16 bytes IV ][ N bytes ciphertext ]
 * Salt and IV are not secret; bundling them with the ciphertext is what
 * lets decryption reconstruct the exact key and cipher state later,
 * without ever storing the password itself anywhere.
 */
function encryptText(plaintext, password) {
  const salt = CryptoJS.lib.WordArray.random(SALT_SIZE_BYTES); // fresh salt, every call
  const iv   = CryptoJS.lib.WordArray.random(IV_SIZE_BYTES);   // fresh IV, every call
  const key  = deriveKey(password, salt);

  const encrypted = CryptoJS.AES.encrypt(plaintext, key, {
    iv: iv,
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.Pkcs7
  });

  // Bundle salt + IV + ciphertext together (via their hex forms) so the
  // single Base64 string decryption receives is self-contained.
  const bundleHex =
    salt.toString(CryptoJS.enc.Hex) +
    iv.toString(CryptoJS.enc.Hex) +
    encrypted.ciphertext.toString(CryptoJS.enc.Hex);

  return CryptoJS.enc.Hex.parse(bundleHex).toString(CryptoJS.enc.Base64);
}

/**
 * Decrypt a Base64 bundle produced by encryptText(). Splits the bundle
 * back into salt / IV / ciphertext, re-derives the same key using the
 * extracted salt and the user-supplied password, then runs AES-CBC in
 * reverse. Throws a descriptive Error for any malformed or tampered
 * input instead of letting a low-level CryptoJS exception escape.
 */
function decryptText(bundleBase64, password) {
  let bundleHex;
  try {
    bundleHex = CryptoJS.enc.Base64.parse(bundleBase64).toString(CryptoJS.enc.Hex);
  } catch (e) {
    throw new Error('That does not look like valid encrypted data.');
  }

  // 16 bytes salt + 16 bytes IV = 32 bytes = 64 hex characters minimum,
  // plus at least one byte of ciphertext.
  const SALT_HEX_LEN = SALT_SIZE_BYTES * 2;
  const IV_HEX_LEN = IV_SIZE_BYTES * 2;
  if (!bundleHex || bundleHex.length <= SALT_HEX_LEN + IV_HEX_LEN) {
    throw new Error('This ciphertext looks incomplete or corrupted.');
  }

  const saltHex   = bundleHex.slice(0, SALT_HEX_LEN);
  const ivHex     = bundleHex.slice(SALT_HEX_LEN, SALT_HEX_LEN + IV_HEX_LEN);
  const cipherHex = bundleHex.slice(SALT_HEX_LEN + IV_HEX_LEN);

  const salt = CryptoJS.enc.Hex.parse(saltHex);
  const iv   = CryptoJS.enc.Hex.parse(ivHex);
  const ciphertext = CryptoJS.enc.Hex.parse(cipherHex);

  const key = deriveKey(password, salt);

  let decrypted;
  try {
    decrypted = CryptoJS.AES.decrypt(
      { ciphertext: ciphertext },
      key,
      { iv: iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 }
    );
  } catch (e) {
    // CryptoJS can throw during padding removal when the key is wrong
    throw new Error('Decryption failed. Check your password and ciphertext.');
  }

  let plaintext;
  try {
    plaintext = decrypted.toString(CryptoJS.enc.Utf8);
  } catch (e) {
    // Wrong password/corrupted data usually produces bytes that are not
    // valid UTF-8, which CryptoJS surfaces as a "Malformed UTF-8 data" error.
    throw new Error('Wrong password or corrupted ciphertext.');
  }

  if (!plaintext) {
    throw new Error('Wrong password or corrupted ciphertext.');
  }

  return plaintext;
}

// ---- Event handlers ---------------------------------------------------------

encryptBtn.addEventListener('click', () => {
  clearAllErrors();

  const password = passwordInput.value;
  const plaintext = plainTextArea.value;

  let hasError = false;
  if (!plaintext.trim()) {
    setFieldError(plainTextError, 'Enter some text to encrypt.');
    hasError = true;
  }
  if (!password) {
    setFieldError(passwordError, 'Enter an encryption key/password.');
    hasError = true;
  }
  if (hasError) {
    setStatus('Please fix the highlighted fields.', 'error');
    return;
  }

  try {
    const result = encryptText(plaintext, password);
    encryptedOutput.value = result;
    // Convenience: also drop the fresh ciphertext into the decrypt panel
    // so the round trip can be demonstrated immediately.
    cipherInput.value = result;
    setStatus('Text encrypted successfully. Salt and IV were freshly generated.', 'success');
  } catch (e) {
    setStatus('Encryption failed: ' + e.message, 'error');
  }
});

decryptBtn.addEventListener('click', () => {
  clearAllErrors();

  const password = passwordInput.value;
  const bundle = cipherInput.value.trim();

  let hasError = false;
  if (!bundle) {
    setFieldError(cipherInputError, 'Paste or generate a ciphertext to decrypt.');
    hasError = true;
  }
  if (!password) {
    setFieldError(passwordError, 'Enter the encryption key/password.');
    hasError = true;
  }
  if (hasError) {
    setStatus('Please fix the highlighted fields.', 'error');
    return;
  }

  try {
    const result = decryptText(bundle, password);
    decryptedOutput.value = result;
    setStatus('Text decrypted successfully.', 'success');
  } catch (e) {
    decryptedOutput.value = '';
    setFieldError(cipherInputError, e.message);
    setStatus('Decryption failed.', 'error');
  }
});

clearEncryptBtn.addEventListener('click', () => {
  plainTextArea.value = '';
  encryptedOutput.value = '';
  setFieldError(plainTextError, '');
  setStatus('', null);
  plainTextArea.focus();
});

clearDecryptBtn.addEventListener('click', () => {
  cipherInput.value = '';
  decryptedOutput.value = '';
  setFieldError(cipherInputError, '');
  setStatus('', null);
  cipherInput.focus();
});

// ---- Copy-to-clipboard buttons ----------------------------------------------
function wireCopyButton(button) {
  button.addEventListener('click', async () => {
    const targetId = button.getAttribute('data-target');
    const targetEl = document.getElementById(targetId);
    const value = targetEl.value;

    if (!value) {
      setStatus('Nothing to copy yet.', 'error');
      return;
    }

    try {
      await navigator.clipboard.writeText(value);
    } catch (e) {
      // Fallback for browsers/contexts without Clipboard API access
      targetEl.removeAttribute('readonly');
      targetEl.select();
      document.execCommand('copy');
      targetEl.setAttribute('readonly', 'true');
    }

    const originalLabel = button.textContent;
    button.textContent = 'Copied';
    button.classList.add('copied');
    setTimeout(() => {
      button.textContent = originalLabel;
      button.classList.remove('copied');
    }, 1400);
  });
}

wireCopyButton(copyEncryptedBtn);
wireCopyButton(copyDecryptedBtn);
