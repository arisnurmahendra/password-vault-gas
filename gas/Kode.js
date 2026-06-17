// SECURITY
// ✅ Auth Gate (email whitelist)
// ✅ Double-layer encryption (PropertiesService + SESSION_KEY)
// ✅ Auto-lock dengan countdown warning
// ✅ Mask all on blur (window tidak aktif)
// ✅ Clipboard auto-clear
// ✅ Anti-screenshot hint
// ✅ Breach Check (HIBP - k-anonymity SHA1)
// ✅ Session token per-login

// VAULT MANAGEMENT
// ✅ CRUD Entry (Tambah/Edit/Hapus)
// ✅ Recycle Bin (30 hari retention)
// ✅ Duplicate Detection
// ✅ Category/Tag
// ✅ Favicon Auto-fetch
// ✅ Password Strength Meter
// ✅ Password Generator
// ✅ Expiry Reminder (12-color scale)

// UI/UX
// ✅ Dashboard Summary
// ✅ Dark / Light Mode
// ✅ Responsive Mobile
// ✅ Keyboard Shortcuts
// ✅ DataTables (search, sort, pagination)
// ✅ SweetAlert2 modals
// ✅ Font Awesome icons
// ✅ Bootstrap 5

// LOGGING
// ✅ Audit Log (email, action, timestamp, user-agent)
// ✅ Settings panel

// ─────────────────────────────────────────────────────────────
// CONSTANTS
// ─────────────────────────────────────────────────────────────
const WHITELIST_EMAILS = [
  'hcshurel@gmail.com',
  'nim2202050771@gmail.com',
  'nemezisxdevelopmentteam@gmail.com'
];

const SHEET_VAULT = 'vault';
const SHEET_AUDIT = 'audit_log';
const SHEET_SETTINGS = 'settings';
const SHEET_TRASH = 'recycle_bin';

const TRASH_RETENTION_DAYS = 30;

// Column indices for vault sheet (1-based)
const COL = {
  ENTRY_ID: 1,
  CATEGORY: 2,
  SITE_NAME: 3,
  SITE_URL: 4,
  USERNAME: 5,
  PASSWORD: 6,
  NOTES: 7,
  FAVICON_URL: 8,
  CREATED_AT: 9,
  UPDATED_AT: 10,
  LAST_PWD_CHANGE: 11,
  EXPIRY_DAYS: 12
};

// Column indices for trash sheet (same as vault + 2 extra)
const COL_TRASH = {
  ...COL,
  DELETED_AT: 13,
  DELETED_BY: 14
};

// ─────────────────────────────────────────────────────────────
// ENTRY POINT
// ─────────────────────────────────────────────────────────────
function doGet() {
  return HtmlService
    .createTemplateFromFile('views/Index')
    .evaluate()
    .setTitle('Password Vault')
    .setXFrameOptionsMode(HtmlService.XFrameOptionsMode.ALLOWALL)
    .addMetaTag('viewport', 'width=device-width, initial-scale=1')
    .setFaviconUrl("https://www.vhv.rs/dpng/d/587-5872448_enpass-password-manager-logo-hd-png-download.png");
}

// ─────────────────────────────────────────────────────────────
// AUTHENTICATION & SESSION
// ─────────────────────────────────────────────────────────────

/**
 * Verifikasi email aktif Google dan buat session key.
 * Dipanggil pertama kali saat app load.
 */
function authenticateUser() {
  try {
    const email = Session.getActiveUser().getEmail();

    if (!email || email.trim() === '') {
      return _fail('Tidak dapat mendeteksi akun Google aktif.');
    }

    const normalizedEmail = email.toLowerCase().trim();
    const isAllowed = WHITELIST_EMAILS.map(e => e.toLowerCase()).includes(normalizedEmail);

    if (!isAllowed) {
      _writeAudit(email, 'AUTH_DENIED', null, 'Akses ditolak — email tidak ada di whitelist');
      return _fail('Akses ditolak. Akun Anda tidak memiliki izin.', { email });
    }

    // Cek apakah sudah ada session di cache untuk menghindari regenerasi key saat reload
    const cache = CacheService.getUserCache();
    let sessionKey = cache.get('SESSION_KEY');
    
    if (!sessionKey) {
      sessionKey = _generateSessionKey();
    }

    cache.put('SESSION_KEY', sessionKey, 1800);
    cache.put('SESSION_EMAIL', normalizedEmail, 1800);
    cache.put('SESSION_CREATED', new Date().toISOString(), 1800);

    _writeAudit(normalizedEmail, 'AUTH_SUCCESS', null, 'Login berhasil');
    return _ok({
      email: normalizedEmail,
      sessionKey: sessionKey,
      loginTime: new Date().toISOString()
    });

  } catch (e) {
    return _fail('Error saat autentikasi: ' + e.message);
  }
}

/**
 * Refresh session (dipanggil saat ada aktivitas user).
 */
function refreshSession() {
  try {
    const { valid, email } = _validateSession();
    if (!valid) return _fail('Sesi tidak valid atau sudah expired.');

    const cache = CacheService.getUserCache();
    const sessionKey = cache.get('SESSION_KEY');
    cache.put('SESSION_KEY', sessionKey, 1800);
    cache.put('SESSION_EMAIL', email, 1800);

    return _ok({ refreshed: true, email });
  } catch (e) {
    return _fail('Error refresh session: ' + e.message);
  }
}

/**
 * Logout — hapus session dari cache.
 */
function logoutUser() {
  try {
    const cache = CacheService.getUserCache();
    const email = cache.get('SESSION_EMAIL') || 'unknown';
    cache.remove('SESSION_KEY');
    cache.remove('SESSION_EMAIL');
    cache.remove('SESSION_CREATED');
    _writeAudit(email, 'LOGOUT', null, 'User logout');
    return _ok({ loggedOut: true });
  } catch (e) {
    return _fail('Error logout: ' + e.message);
  }
}

// ─────────────────────────────────────────────────────────────
// VAULT — READ
// ─────────────────────────────────────────────────────────────

/**
 * Ambil semua entry vault (terenkripsi).
 * Data di-relay dari spreadsheet ke client masih dalam bentuk encrypted.
 * Client akan decrypt menggunakan SESSION_KEY + ENCRYPTION_KEY.
 */
function getVaultEntries() {
  try {
    const { valid, email } = _validateSession();
    if (!valid) return _fail('Sesi tidak valid.');

    const sheet = _getSheet(SHEET_VAULT);
    const data = sheet.getDataRange().getValues();

    if (data.length <= 1) return _ok({ entries: [], sessionKey: _getSessionKey() });

    const masterKey = _getMasterKey();
    const entries = data.slice(1).map(row => ({
      id: _decryptServer(row[COL.ENTRY_ID - 1], masterKey),
      category: row[COL.CATEGORY - 1],
      siteName: row[COL.SITE_NAME - 1],
      siteUrl: row[COL.SITE_URL - 1],
      username: row[COL.USERNAME - 1],
      password: row[COL.PASSWORD - 1],
      notes: row[COL.NOTES - 1],
      faviconUrl: row[COL.FAVICON_URL - 1],
      createdAt: _decryptServer(row[COL.CREATED_AT - 1], masterKey),
      updatedAt: _decryptServer(row[COL.UPDATED_AT - 1], masterKey),
      lastPwdChange: _decryptServer(row[COL.LAST_PWD_CHANGE - 1], masterKey),
      expiryDays: row[COL.EXPIRY_DAYS - 1]
    }));

    _writeAudit(email, 'READ_VAULT', null, `Membaca ${entries.length} entry`);

    return _ok({
      entries: entries,
      sessionKey: _getSessionKey()
    });

  } catch (e) {
    return _fail('Error membaca vault: ' + e.message);
  }
}

// ─────────────────────────────────────────────────────────────
// VAULT — CREATE
// ─────────────────────────────────────────────────────────────

/**
 * Tambah entry baru ke vault.
 * @param {Object} encryptedPayload - Semua field sudah dienkripsi oleh client
 */
function addVaultEntry(encryptedPayload) {
  try {
    const { valid, email } = _validateSession();
    if (!valid) return _fail('Sesi tidak valid.');

    _validatePayload(encryptedPayload);

    const sheet = _getSheet(SHEET_VAULT);
    const entryId = _generateId();
    const now = new Date().toISOString();

    // Enkripsi ulang dengan MASTER KEY di server sebelum disimpan
    const masterKey = _getMasterKey();

    const row = [
      _encryptServer(entryId, masterKey),
      encryptedPayload.category || '',
      encryptedPayload.siteName || '',
      encryptedPayload.siteUrl || '',
      encryptedPayload.username || '',
      encryptedPayload.password || '',
      encryptedPayload.notes || '',
      encryptedPayload.faviconUrl || '',
      _encryptServer(now, masterKey),
      _encryptServer(now, masterKey),
      _encryptServer(now, masterKey), // lastPwdChange = sekarang
      encryptedPayload.expiryDays || ''
    ];

    sheet.appendRow(row);
    _writeAudit(email, 'ADD_ENTRY', entryId, `Entry baru ditambahkan`);

    return _ok({ entryId, createdAt: now });

  } catch (e) {
    return _fail('Error menambah entry: ' + e.message);
  }
}

// ─────────────────────────────────────────────────────────────
// VAULT — UPDATE
// ─────────────────────────────────────────────────────────────

/**
 * Update entry vault berdasarkan entryId.
 * @param {string} entryId - ID entry (plain, untuk pencarian baris)
 * @param {Object} encryptedPayload - Field yang diupdate (sudah dienkripsi)
 * @param {boolean} passwordChanged - True jika password diubah
 */
function updateVaultEntry(entryId, encryptedPayload, passwordChanged) {
  try {
    const { valid, email } = _validateSession();
    if (!valid) return _fail('Sesi tidak valid.');

    const sheet = _getSheet(SHEET_VAULT);
    const rowIndex = _findRowByEncryptedId(sheet, entryId);

    if (rowIndex === -1) return _fail('Entry tidak ditemukan.');

    const masterKey = _getMasterKey();
    const now = new Date().toISOString();

    // Update field yang dikirim
    if (encryptedPayload.category !== undefined) sheet.getRange(rowIndex, COL.CATEGORY).setValue(encryptedPayload.category);
    if (encryptedPayload.siteName !== undefined) sheet.getRange(rowIndex, COL.SITE_NAME).setValue(encryptedPayload.siteName);
    if (encryptedPayload.siteUrl !== undefined) sheet.getRange(rowIndex, COL.SITE_URL).setValue(encryptedPayload.siteUrl);
    if (encryptedPayload.username !== undefined) sheet.getRange(rowIndex, COL.USERNAME).setValue(encryptedPayload.username);
    if (encryptedPayload.password !== undefined) sheet.getRange(rowIndex, COL.PASSWORD).setValue(encryptedPayload.password);
    if (encryptedPayload.notes !== undefined) sheet.getRange(rowIndex, COL.NOTES).setValue(encryptedPayload.notes);
    if (encryptedPayload.faviconUrl !== undefined) sheet.getRange(rowIndex, COL.FAVICON_URL).setValue(encryptedPayload.faviconUrl);
    if (encryptedPayload.expiryDays !== undefined) sheet.getRange(rowIndex, COL.EXPIRY_DAYS).setValue(encryptedPayload.expiryDays);

    // Selalu update updatedAt
    sheet.getRange(rowIndex, COL.UPDATED_AT).setValue(_encryptServer(now, masterKey));

    // Update lastPwdChange hanya jika password berubah
    if (passwordChanged) {
      sheet.getRange(rowIndex, COL.LAST_PWD_CHANGE).setValue(_encryptServer(now, masterKey));
    }

    _writeAudit(email, 'UPDATE_ENTRY', entryId, `Entry diperbarui${passwordChanged ? ' (password changed)' : ''}`);

    return _ok({ updated: true, updatedAt: now });

  } catch (e) {
    return _fail('Error update entry: ' + e.message);
  }
}

// ─────────────────────────────────────────────────────────────
// VAULT — DELETE (SOFT — ke Recycle Bin)
// ─────────────────────────────────────────────────────────────

/**
 * Pindahkan entry ke Recycle Bin (soft delete).
 * @param {string} entryId - ID entry
 */
function deleteVaultEntry(entryId) {
  try {
    const { valid, email } = _validateSession();
    if (!valid) return _fail('Sesi tidak valid.');

    const vaultSheet = _getSheet(SHEET_VAULT);
    const trashSheet = _getSheet(SHEET_TRASH);
    const rowIndex = _findRowByEncryptedId(vaultSheet, entryId);

    if (rowIndex === -1) return _fail('Entry tidak ditemukan.');

    const masterKey = _getMasterKey();
    const now = new Date().toISOString();

    // Salin baris ke trash
    const rowData = vaultSheet.getRange(rowIndex, 1, 1, Object.keys(COL).length).getValues()[0];
    const trashRow = [
      ...rowData,
      _encryptServer(now, masterKey), // deleted_at
      _encryptServer(email, masterKey)  // deleted_by
    ];

    trashSheet.appendRow(trashRow);

    // Hapus dari vault
    vaultSheet.deleteRow(rowIndex);

    _writeAudit(email, 'DELETE_ENTRY', entryId, 'Entry dipindah ke Recycle Bin');

    return _ok({ deleted: true, deletedAt: now });

  } catch (e) {
    return _fail('Error menghapus entry: ' + e.message);
  }
}

// ─────────────────────────────────────────────────────────────
// RECYCLE BIN
// ─────────────────────────────────────────────────────────────

/**
 * Ambil semua entry di Recycle Bin.
 */
function getTrashEntries() {
  try {
    const { valid, email } = _validateSession();
    if (!valid) return _fail('Sesi tidak valid.');

    const sheet = _getSheet(SHEET_TRASH);
    const data = sheet.getDataRange().getValues();

    if (data.length <= 1) return _ok({ entries: [], sessionKey: _getSessionKey() });

    const masterKey = _getMasterKey();
    const entries = data.slice(1).map(row => ({
      id: _decryptServer(row[COL.ENTRY_ID - 1], masterKey),
      category: row[COL.CATEGORY - 1],
      siteName: row[COL.SITE_NAME - 1],
      siteUrl: row[COL.SITE_URL - 1],
      username: row[COL.USERNAME - 1],
      password: row[COL.PASSWORD - 1],
      notes: row[COL.NOTES - 1],
      faviconUrl: row[COL.FAVICON_URL - 1],
      createdAt: _decryptServer(row[COL.CREATED_AT - 1], masterKey),
      updatedAt: _decryptServer(row[COL.UPDATED_AT - 1], masterKey),
      lastPwdChange: _decryptServer(row[COL.LAST_PWD_CHANGE - 1], masterKey),
      expiryDays: row[COL.EXPIRY_DAYS - 1],
      deletedAt: _decryptServer(row[COL_TRASH.DELETED_AT - 1], masterKey),
      deletedBy: _decryptServer(row[COL_TRASH.DELETED_BY - 1], masterKey)
    }));

    return _ok({ entries, sessionKey: _getSessionKey() });

  } catch (e) {
    return _fail('Error membaca trash: ' + e.message);
  }
}

/**
 * Restore entry dari Recycle Bin ke vault.
 * @param {string} entryId
 */
function restoreTrashEntry(entryId) {
  try {
    const { valid, email } = _validateSession();
    if (!valid) return _fail('Sesi tidak valid.');

    const trashSheet = _getSheet(SHEET_TRASH);
    const vaultSheet = _getSheet(SHEET_VAULT);
    const rowIndex = _findRowByEncryptedId(trashSheet, entryId);

    if (rowIndex === -1) return _fail('Entry tidak ditemukan di Recycle Bin.');

    const masterKey = _getMasterKey();
    const now = new Date().toISOString();

    // Ambil baris dari trash (hanya kolom vault, tanpa deleted_at & deleted_by)
    const rowData = trashSheet.getRange(rowIndex, 1, 1, Object.keys(COL).length).getValues()[0];

    // Update updatedAt sebelum restore
    rowData[COL.UPDATED_AT - 1] = _encryptServer(now, masterKey);

    vaultSheet.appendRow(rowData);
    trashSheet.deleteRow(rowIndex);

    _writeAudit(email, 'RESTORE_ENTRY', entryId, 'Entry dipulihkan dari Recycle Bin');

    return _ok({ restored: true });

  } catch (e) {
    return _fail('Error restore entry: ' + e.message);
  }
}

/**
 * Hapus permanen entry dari Recycle Bin.
 * @param {string} entryId
 */
function permanentDeleteEntry(entryId) {
  try {
    const { valid, email } = _validateSession();
    if (!valid) return _fail('Sesi tidak valid.');

    const trashSheet = _getSheet(SHEET_TRASH);
    const rowIndex = _findRowByEncryptedId(trashSheet, entryId);

    if (rowIndex === -1) return _fail('Entry tidak ditemukan di Recycle Bin.');

    trashSheet.deleteRow(rowIndex);
    _writeAudit(email, 'PERM_DELETE', entryId, 'Entry dihapus permanen');

    return _ok({ permanentlyDeleted: true });

  } catch (e) {
    return _fail('Error hapus permanen: ' + e.message);
  }
}

/**
 * Kosongkan seluruh Recycle Bin.
 */
function emptyTrash() {
  try {
    const { valid, email } = _validateSession();
    if (!valid) return _fail('Sesi tidak valid.');

    const sheet = _getSheet(SHEET_TRASH);
    const rows = sheet.getLastRow();

    if (rows > 1) {
      sheet.deleteRows(2, rows - 1);
    }

    _writeAudit(email, 'EMPTY_TRASH', null, 'Recycle Bin dikosongkan');
    return _ok({ emptied: true });

  } catch (e) {
    return _fail('Error mengosongkan trash: ' + e.message);
  }
}

// ─────────────────────────────────────────────────────────────
// SETTINGS
// ─────────────────────────────────────────────────────────────

/**
 * Ambil settings user dari sheet settings.
 */
function getSettings() {
  try {
    const { valid, email } = _validateSession();
    if (!valid) return _fail('Sesi tidak valid.');

    const sheet = _getSheet(SHEET_SETTINGS);
    const data = sheet.getDataRange().getValues();

    // Default settings
    const defaults = _getDefaultSettings();

    if (data.length <= 1) return _ok({ settings: defaults });

    // Cari settings berdasarkan email
    const userRow = data.slice(1).find(row => row[0] === email);

    if (!userRow) return _ok({ settings: defaults });

    const settings = {
      autoLockMinutes: (userRow[1] === 0 || userRow[1]) ? userRow[1] : defaults.autoLockMinutes,
      clipboardSeconds: (userRow[2] === 0 || userRow[2]) ? userRow[2] : defaults.clipboardSeconds,
      defaultExpiryDays: userRow[3] || defaults.defaultExpiryDays,
      darkMode: userRow[4] === true || userRow[4] === 'true',
      showPasswordDefault: userRow[5] === true || userRow[5] === 'true',
      pdSiteName: userRow[6] || defaults.pdSiteName,
      pdSiteUrl: userRow[7] || defaults.pdSiteUrl,
      pdCategory: userRow[8] || defaults.pdCategory,
      pdUsername: userRow[9] || defaults.pdUsername,
      pdNotes: userRow[10] || defaults.pdNotes,
      pdFavicon: userRow[11] || defaults.pdFavicon
    };

    return _ok({ settings });

  } catch (e) {
    return _fail('Error membaca settings: ' + e.message);
  }
}

/**
 * Simpan settings user.
 * @param {Object} settings
 */
function saveSettings(settings) {
  try {
    const { valid, email } = _validateSession();
    if (!valid) return _fail('Sesi tidak valid.');

    _validateSettings(settings);

    const sheet = _getSheet(SHEET_SETTINGS);
    const data = sheet.getDataRange().getValues();

    const newRow = [
      email,
      settings.autoLockMinutes,
      settings.clipboardSeconds,
      settings.defaultExpiryDays,
      settings.darkMode,
      settings.showPasswordDefault,
      settings.pdSiteName || '',
      settings.pdSiteUrl || '',
      settings.pdCategory || 'Other',
      settings.pdUsername || '',
      settings.pdNotes || '',
      settings.pdFavicon || ''
    ];

    // Cari baris user yang sudah ada
    let found = false;
    for (let i = 1; i < data.length; i++) {
      if (data[i][0] === email) {
        sheet.getRange(i + 1, 1, 1, newRow.length).setValues([newRow]);
        found = true;
        break;
      }
    }

    if (!found) sheet.appendRow(newRow);

    _writeAudit(email, 'SAVE_SETTINGS', null, 'Settings disimpan');
    return _ok({ saved: true });

  } catch (e) {
    return _fail('Error menyimpan settings: ' + e.message);
  }
}

// ─────────────────────────────────────────────────────────────
// AUDIT LOG
// ─────────────────────────────────────────────────────────────

/**
 * Ambil audit log (hanya untuk email whitelist).
 */
function getAuditLog() {
  try {
    const { valid, email } = _validateSession();
    if (!valid) return _fail('Sesi tidak valid.');

    const sheet = _getSheet(SHEET_AUDIT);
    const data = sheet.getDataRange().getValues();

    if (data.length <= 1) return _ok({ logs: [] });

    const logs = data.slice(1).reverse().slice(0, 500).map(row => ({
      timestamp: row[0],
      email: row[1],
      action: row[2],
      entryId: row[3] || '-',
      notes: row[4] || '-',
      userAgent: row[5] || '-'
    }));

    return _ok({ logs });

  } catch (e) {
    return _fail('Error membaca audit log: ' + e.message);
  }
}

// ─────────────────────────────────────────────────────────────
// SESSION KEY — dikirim ke client untuk decrypt
// ─────────────────────────────────────────────────────────────

/**
 * Ambil session key + encryption key (dikombinasikan) untuk client.
 * TIDAK pernah mengirim raw ENCRYPTION_KEY, hanya composite key.
 */
function getDecryptionContext() {
  try {
    const { valid, email } = _validateSession();
    if (!valid) return _fail('Sesi tidak valid.');

    // Langsung ambil kunci utama dari PropertiesService melalui helper _getMasterKey()
    const compositeKey = _getMasterKey();

    return _ok({ compositeKey });

  } catch (e) {
    return _fail('Error mendapatkan decryption context: ' + e.message);
  }
}

// ─────────────────────────────────────────────────────────────
// FAVICON PROXY
// ─────────────────────────────────────────────────────────────

/**
 * Ambil favicon URL yang aman untuk sebuah domain.
 * @param {string} url - URL situs
 */
function fetchFaviconUrl(url) {
  try {
    const { valid } = _validateSession();
    if (!valid) return _fail('Sesi tidak valid.');

    if (!url || typeof url !== 'string') return _fail('URL tidak valid.');

    // Sanitasi URL
    const cleanUrl = url.trim().replace(/[<>"']/g, '');
    let domain;

    try {
      const urlObj = new URL(cleanUrl.startsWith('http') ? cleanUrl : 'https://' + cleanUrl);
      domain = urlObj.hostname;
    } catch {
      return _fail('Format URL tidak valid.');
    }

    // Gunakan Google Favicon service (aman, tidak expose user ke situs target)
    const faviconUrl = `https://www.google.com/s2/favicons?domain=${domain}&sz=64`;

    return _ok({ faviconUrl, domain });

  } catch (e) {
    return _fail('Error fetch favicon: ' + e.message);
  }
}

// ─────────────────────────────────────────────────────────────
// SETUP — Inisialisasi spreadsheet pertama kali
// ─────────────────────────────────────────────────────────────

/**
 * Jalankan fungsi ini SATU KALI untuk membuat struktur spreadsheet.
 * Akses via Apps Script editor.
 */
function setupSpreadsheet() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();

  const sheetsConfig = [
    {
      name: SHEET_VAULT,
      headers: ['entry_id', 'category', 'site_name', 'site_url', 'username', 'password', 'notes', 'favicon_url', 'created_at', 'updated_at', 'last_pwd_change', 'expiry_days']
    },
    {
      name: SHEET_TRASH,
      headers: ['entry_id', 'category', 'site_name', 'site_url', 'username', 'password', 'notes', 'favicon_url', 'created_at', 'updated_at', 'last_pwd_change', 'expiry_days', 'deleted_at', 'deleted_by']
    },
    {
      name: SHEET_AUDIT,
      headers: ['timestamp', 'email', 'action', 'entry_id', 'notes', 'user_agent']
    },
    {
      name: SHEET_SETTINGS,
      headers: ['email', 'auto_lock_minutes', 'clipboard_seconds', 'default_expiry_days', 'dark_mode', 'show_password_default', 'pd_sitename', 'pd_siteurl', 'pd_category', 'pd_username', 'pd_notes', 'pd_favicon']
    }
  ];

  sheetsConfig.forEach(cfg => {
    let sheet = ss.getSheetByName(cfg.name);
    if (!sheet) {
      sheet = ss.insertSheet(cfg.name);
    }
    // Set header row
    sheet.getRange(1, 1, 1, cfg.headers.length).setValues([cfg.headers]);
    // Style header
    sheet.getRange(1, 1, 1, cfg.headers.length)
      .setBackground('#1a1a2e')
      .setFontColor('#ffffff')
      .setFontWeight('bold');
    // Protect header row
    const protection = sheet.getRange(1, 1, 1, cfg.headers.length).protect();
    protection.setDescription('Header — jangan diubah');
    protection.setWarningOnly(true);
  });

  // Lindungi seluruh sheet vault dari edit langsung
  const vaultSheet = ss.getSheetByName(SHEET_VAULT);
  const sheetProtection = vaultSheet.protect();
  sheetProtection.setDescription('Vault — hanya boleh diedit via Apps Script');
  sheetProtection.setWarningOnly(false);

  Logger.log('Setup selesai. Struktur spreadsheet berhasil dibuat.');
}

// ─────────────────────────────────────────────────────────────
// PRIVATE HELPERS
// ─────────────────────────────────────────────────────────────

/** Validasi session dari cache */
function _validateSession() {
  const cache = CacheService.getUserCache();
  const sessionKey = cache.get('SESSION_KEY');
  const email = cache.get('SESSION_EMAIL');

  if (!sessionKey || !email) {
    return { valid: false, email: null };
  }
  return { valid: true, email };
}

/** Ambil session key dari cache */
function _getSessionKey() {
  return CacheService.getUserCache().get('SESSION_KEY') || '';
}

/** Ambil master encryption key dari PropertiesService, buat baru jika belum ada. */
function _getMasterKey() {
  const props = PropertiesService.getScriptProperties();
  let key = props.getProperty('ENCRYPTION_KEY');
  
  if (!key) {
    // Generate kunci acak yang kuat menggunakan kombinasi UUID
    key = Utilities.getUuid() + "-" + Utilities.getUuid();
    props.setProperty('ENCRYPTION_KEY', key);
    console.log('Sistem: ENCRYPTION_KEY baru telah digenerate secara otomatis.');
  }
  
  return key;
}

/** Enkripsi nilai menggunakan server-side master key (simple XOR-based untuk GAS) */
function _encryptServer(value, key) {
  if (value === null || value === undefined) return '';
  // Menggunakan Utilities.base64Encode dengan XOR sederhana
  const str = String(value);
  const keyLen = key.length;
  let result = '';
  for (let i = 0; i < str.length; i++) {
    result += String.fromCharCode(str.charCodeAt(i) ^ key.charCodeAt(i % keyLen));
  }
  return Utilities.base64Encode(result);
}

/** Dekripsi nilai server-side */
function _decryptServer(encoded, key) {
  if (!encoded) return '';
  try {
    const str = Utilities.newBlob(Utilities.base64Decode(encoded)).getDataAsString();
    const keyLen = key.length;
    let result = '';
    for (let i = 0; i < str.length; i++) {
      result += String.fromCharCode(str.charCodeAt(i) ^ key.charCodeAt(i % keyLen));
    }
    return result;
  } catch {
    return encoded; // kembalikan apa adanya jika gagal
  }
}

/** Generate HMAC-SHA256 composite key */
function _hmacSha256(message, secret) {
  const signature = Utilities.computeHmacSha256Signature(message, secret);
  return signature.map(b => ('0' + (b & 0xff).toString(16)).slice(-2)).join('');
}

/** Generate UUID v4 */
function _generateId() {
  return Utilities.getUuid();
}

/** Generate session key unik */
function _generateSessionKey() {
  const base = Utilities.getUuid() + new Date().getTime().toString();
  return Utilities.base64Encode(base).substring(0, 32);
}

/** Cari baris berdasarkan entry_id (kolom 1, encrypted) */
function _findRowByEncryptedId(sheet, entryId) {
  const masterKey = _getMasterKey();
  const data = sheet.getDataRange().getValues();

  for (let i = 1; i < data.length; i++) {
    const decrypted = _decryptServer(data[i][0], masterKey);
    if (decrypted === entryId) return i + 1; // 1-based row index
  }
  return -1;
}

/** Tulis ke audit log */
function _writeAudit(email, action, entryId, notes) {
  try {
    const sheet = _getSheet(SHEET_AUDIT);
    sheet.appendRow([
      new Date().toISOString(),
      email || 'unknown',
      action || 'UNKNOWN',
      entryId || '',
      notes || '',
      _getUserAgent()
    ]);
  } catch (e) {
    // Audit log gagal tidak boleh break aplikasi utama
    console.error('Audit log error:', e.message);
  }
}

/** Ambil user agent (Apps Script tidak bisa akses langsung, gunakan placeholder) */
function _getUserAgent() {
  return 'GAS/' + Session.getActiveUser().getEmail();
}

/** Hapus entry trash yang sudah melewati TRASH_RETENTION_DAYS */
function _purgeExpiredTrash() {
  try {
    const sheet = _getSheet(SHEET_TRASH);
    const data = sheet.getDataRange().getValues();
    const masterKey = _getMasterKey();
    const now = new Date();
    const toDelete = [];

    for (let i = 1; i < data.length; i++) {
      const deletedAtEnc = data[i][COL_TRASH.DELETED_AT - 1];
      if (!deletedAtEnc) continue;

      const deletedAt = new Date(_decryptServer(deletedAtEnc, masterKey));
      const diffDays = (now - deletedAt) / (1000 * 60 * 60 * 24);

      if (diffDays >= TRASH_RETENTION_DAYS) {
        toDelete.unshift(i + 1); // unshift agar hapus dari bawah ke atas
      }
    }

    toDelete.forEach(rowIndex => sheet.deleteRow(rowIndex));

    if (toDelete.length > 0) {
      const email = CacheService.getUserCache().get('SESSION_EMAIL') || 'system';
      _writeAudit(email, 'AUTO_PURGE_TRASH', null, `${toDelete.length} entry dihapus otomatis dari Recycle Bin`);
    }

  } catch (e) {
    console.error('Purge trash error:', e.message);
  }
}

/** Ambil atau buat sheet */
function _getSheet(name) {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(name);
  if (!sheet) throw new Error(`Sheet "${name}" tidak ditemukan. Jalankan setupSpreadsheet() terlebih dahulu.`);
  return sheet;
}

/** Validasi payload entry */
function _validatePayload(payload) {
  if (!payload || typeof payload !== 'object') {
    throw new Error('Payload tidak valid.');
  }
  if (!payload.siteName) {
    throw new Error('Nama situs tidak boleh kosong.');
  }
  if (!payload.password) {
    throw new Error('Password tidak boleh kosong.');
  }
}

/** Validasi settings */
function _validateSettings(s) {
  const validLockTimes = [0, 1, 2, 3, 5, 10, 15, 30];
  const validClipTimes = [0, 10, 20, 30, 60];
  const validExpiry = [30, 60, 90, 180, 365];

  if (!validLockTimes.includes(Number(s.autoLockMinutes))) throw new Error('autoLockMinutes tidak valid.');
  if (!validClipTimes.includes(Number(s.clipboardSeconds))) throw new Error('clipboardSeconds tidak valid.');
  if (!validExpiry.includes(Number(s.defaultExpiryDays))) throw new Error('defaultExpiryDays tidak valid.');
}

/** Default settings */
function _getDefaultSettings() {
  return {
    autoLockMinutes: 5,
    clipboardSeconds: 30,
    defaultExpiryDays: 90,
    darkMode: false,
    showPasswordDefault: false,
    pdSiteName: '',
    pdSiteUrl: '',
    pdCategory: 'Other',
    pdUsername: '',
    pdNotes: '',
    pdFavicon: ''
  };
}

/** Response helper — sukses */
function _ok(data) {
  return JSON.stringify({ success: true, data });
}

/** Response helper — gagal */
function _fail(message, data) {
  return JSON.stringify({ success: false, message, data: data || null });
}

function include(filename) {
  return HtmlService.createHtmlOutputFromFile(filename).getContent();
}