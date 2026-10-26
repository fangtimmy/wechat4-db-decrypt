// Experimental Windows key hook for future WeChat versions.
// WeChat 4.1.15 does not use CNG for database AES, so this is only a
// best-effort fallback; the verified path is the read-only Config.Cipher scan.
'use strict';

const seen = new Set();
const hooked = new Set();

function toHex(buffer) {
  return Array.from(new Uint8Array(buffer), b => ('0' + b.toString(16)).slice(-2)).join('');
}

function report(tag, pointer, length) {
  try {
    if (!pointer || pointer.isNull()) return;
    if (length !== 32) return;
    const hex = toHex(pointer.readByteArray(32));
    if (seen.has(hex)) return;
    seen.add(hex);
    send('KEY32 ' + tag + ' ' + hex);
  } catch (e) {
    // Unreadable pointer at teardown; ignore.
  }
}

function tryResolve(moduleName, name) {
  try {
    const module = Process.getModuleByName(moduleName);
    if (module) {
      const address = module.getExportByName(name);
      if (address) return address;
    }
  } catch (e) {}
  try { return Module.findGlobalExportByName(name); } catch (e) {}
  try { return Module.findExportByName(null, name); } catch (e) {}
  return null;
}

function attach(address, name, callback) {
  if (!address) return false;
  const key = address.toString();
  if (hooked.has(key)) return true;
  try {
    Interceptor.attach(address, { onEnter: callback });
    hooked.add(key);
    return true;
  } catch (e) {
    send('MISS ' + name + ' ' + e);
    return false;
  }
}

function install() {
  let count = 0;

  const generate = tryResolve('bcrypt.dll', 'BCryptGenerateSymmetricKey');
  if (attach(generate, 'BCryptGenerateSymmetricKey', function (args) {
    report('BCryptGenerateSymmetricKey', args[4], args[5].toInt32());
  })) count++;

  const importKey = tryResolve('bcrypt.dll', 'BCryptImportKey');
  if (attach(importKey, 'BCryptImportKey', function (args) {
    report('BCryptImportKey', args[6], args[7].toInt32());
  })) count++;

  const pbkdf = tryResolve('bcrypt.dll', 'BCryptDeriveKeyPBKDF2');
  if (attach(pbkdf, 'BCryptDeriveKeyPBKDF2', function (args) {
    report('BCryptDeriveKeyPBKDF2', args[1], args[2].toInt32());
  })) count++;

  for (const name of ['EVP_CipherInit_ex', 'EVP_DecryptInit_ex', 'EVP_EncryptInit_ex']) {
    const address = tryResolve(null, name);
    if (address && attach(address, name, function (args) {
      // key is the 4th argument in EVP_CipherInit_ex(ctx, cipher, engine, key, iv, enc)
      report(name, args[3], 32);
    })) count++;
  }

  send('ARMED ' + count + ' hooks');
  if (count > 0) {
    clearInterval(timer);
  }
}

let timer = setInterval(install, 500);
install();
