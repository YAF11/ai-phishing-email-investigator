'use strict';

// ============================================================
// AI Phishing Email Investigator — Frontend Script
// IBM SkillsBuild Capstone Project
// ============================================================

// ============================================================
// Constants
// ============================================================
const STORAGE_KEY    = 'phishguard_history';
const LANG_KEY       = 'phishguard_language';
const MAX_HISTORY    = 100;
const API_ENDPOINT       = '/api/analyze';
const HEALTH_ENDPOINT    = '/api/health';
const TRANSLATE_ENDPOINT = '/api/translate';

// ============================================================
// Internationalization (i18n)
// ============================================================

const TRANSLATIONS = {
  id: {
    // Navigation
    nav_dashboard:   'Dasbor',
    nav_investigate: 'Investigasi',
    nav_history:     'Riwayat',
    nav_about:       'Tentang',

    // Topbar
    topbar_new_investigation: 'Investigasi Baru',
    topbar_title_dashboard:   'Dasbor',
    topbar_title_investigate: 'Investigasi',
    topbar_title_history:     'Riwayat Investigasi',
    topbar_title_about:       'Tentang',

    // API Status
    status_checking:        'Memeriksa...',
    status_connected:       'API Terhubung',
    status_not_configured:  'API Belum Dikonfigurasi',
    status_offline:         'Server Offline',

    // Language selector
    lang_label: 'Bahasa',
    lang_id:    'Bahasa Indonesia',
    lang_en:    'English',

    // Dashboard
    dash_title:    'Dasbor Investigasi',
    dash_subtitle: 'Analisis ancaman phishing berbasis AI dan investigasi keamanan email',
    dash_new_btn:  'Investigasi Baru',
    stat_total:    'Total Investigasi',
    stat_high:     'Risiko TINGGI / KRITIS',
    stat_medium:   'Risiko SEDANG',
    stat_low:      'Risiko RENDAH',
    recent_title:  'Aktivitas Investigasi Terbaru',
    recent_records_1: 'catatan',
    recent_records_n: 'catatan',
    recent_col_sender:  'Pengirim',
    recent_col_subject: 'Subjek',
    recent_col_risk:    'Tingkat Risiko',
    recent_col_class:   'Klasifikasi',
    recent_col_date:    'Tanggal',
    recent_col_action:  'Tindakan',
    recent_view_btn:    'Lihat',
    recent_empty:       'Belum ada investigasi. Mulai investigasi pertama Anda untuk melihat aktivitas di sini.',
    recent_start_btn:   'Mulai Investigasi',

    // API Warning Banner
    api_warning_title: 'API Belum Dikonfigurasi',
    api_warning_body:  'Analisis AI tidak tersedia. Salin',
    api_warning_body2: 'ke',
    api_warning_body3: 'dan atur',
    api_warning_body4: 'untuk mengaktifkan investigasi.',

    // Investigate page
    inv_title:    'Investigasi Email',
    inv_subtitle: 'Kirimkan detail email untuk analisis phishing berbasis AI',
    inv_form_card_title:   'Informasi Email',
    inv_required_badge:    'Kolom wajib ditandai *',
    inv_section_sender:    'Detail Pengirim',
    inv_label_sender_name: 'Nama Pengirim *',
    inv_ph_sender_name:    'mis. Tim Keamanan',
    inv_label_sender_email:'Alamat Email Pengirim *',
    inv_ph_sender_email:   'mis. keamanan@contoh.com',
    inv_label_subject:     'Subjek Email *',
    inv_ph_subject:        'mis. Urgen! Akun Anda Akan Ditangguhkan',
    inv_section_message:   'Konten Pesan',
    inv_label_body:        'Isi Email *',
    inv_ph_body:           'Tempelkan teks isi email lengkap di sini...',
    inv_char_count:        '/ 10.000 karakter',
    inv_label_url:         'URL / Tautan',
    inv_optional:          '(opsional)',
    inv_ph_url:            'Tempelkan URL mencurigakan sebagai teks biasa — jangan diklik',
    inv_hint_url:          'Tempelkan URL sebagai teks biasa. URL hanya akan dianalisis secara struktural.',
    inv_section_auth:      'Autentikasi & Header',
    inv_label_spf:         'Hasil SPF',
    inv_label_dkim:        'Hasil DKIM',
    inv_label_dmarc:       'Hasil DMARC',
    inv_opt_not_provided:  'Tidak tersedia',
    inv_label_headers:     'Header Email Mentah',
    inv_ph_headers:        'Tempelkan header email mentah di sini...',
    inv_hint_headers:      'Header From: / Reply-To: / Received: dan hasil autentikasi.',
    btn_reset:             'Reset Formulir',
    btn_analyze:           'Analisis Email',
    btn_analyzing:         'Menganalisis...',

    // Loading / Error states
    loading_title:    'Menganalisis Email',
    loading_subtitle: 'Investigasi AI sedang berjalan. Ini mungkin memakan waktu hingga 30 detik.',
    error_default_title: 'Analisis Gagal',
    error_connection_title: 'Kesalahan Koneksi',
    error_connection_msg: 'Tidak dapat terhubung ke server. Pastikan backend berjalan di port 3000.',
    error_server_msg: 'Kesalahan server ({status}). Silakan coba lagi.',
    btn_retry: 'Coba Lagi',

    // Results: Risk Banner labels
    risk_label:       'TINGKAT RISIKO',
    confidence_label: 'KEYAKINAN',

    // Results: Section headings
    result_sec1:  '1. Ringkasan Eksekutif',
    result_sec2:  '2. Informasi Email',
    result_sec3:  '3. Analisis Identitas Pengirim',
    result_sec4:  '4. Deteksi Rekayasa Sosial',
    result_sec5:  '5. Analisis URL dan Domain',
    result_sec6:  '6. Analisis Header Email & Autentikasi',
    result_sec7:  '7. Indikator Mencurigakan',
    result_sec8:  '8. Analisis Bukti',
    result_sec910:'9–10. Klasifikasi Ancaman & Penilaian Risiko',
    result_sec11: '11. Tindakan yang Direkomendasikan',
    result_sec12: '12. Keterbatasan Investigasi',

    // Results: Email info table labels
    info_sender_name:  'Nama Pengirim',
    info_sender_email: 'Email Pengirim',
    info_sender_domain:'Domain Pengirim',
    info_subject:      'Subjek',
    info_urls:         'URL Disediakan',
    info_headers:      'Header',
    info_spf:          'SPF',
    info_dkim:         'DKIM',
    info_dmarc:        'DMARC',
    info_none:         'Tidak ada',
    info_not_provided: 'Tidak tersedia',

    // Results: Evidence sections
    evidence_confirmed:   '✅ Observasi Terkonfirmasi',
    evidence_suspicious:  '⚠️ Indikator Mencurigakan',
    evidence_unverified:  '❓ Asumsi Belum Terverifikasi',
    evidence_no_items:    'Tidak ada item dalam kategori ini.',

    // Results: Indicators
    indicator_category_prefix: 'Kategori:',

    // Results: Classification block
    classification_label: 'Klasifikasi Ancaman',
    risk_level_label:     'Tingkat Risiko',
    confidence_level_label: 'Tingkat Keyakinan',
    no_explanation:       'Tidak ada penjelasan tersedia.',

    // Results: Empty lists
    no_indicators_msg: 'Tidak ada indikator mencurigakan signifikan yang teridentifikasi dari informasi yang tersedia.',
    no_items_provided: 'Tidak ada item yang disediakan.',

    // Results: Modal
    modal_title:               'Laporan Investigasi',
    modal_exec_summary:        'Ringkasan Eksekutif',
    modal_sender_analysis:     'Analisis Identitas Pengirim',
    modal_social_engineering:  'Deteksi Rekayasa Sosial',
    modal_suspicious_indicators: 'Indikator Mencurigakan',
    modal_risk_explanation:    'Penjelasan Risiko',
    modal_recommended_actions: 'Tindakan yang Direkomendasikan',
    modal_no_data:             'Tidak ada data hasil tersedia.',

    // Results: Report footer
    report_footer: 'Laporan ini dibuat oleh AI Phishing Email Investigator. Tidak ada verifikasi eksternal, pemindaian URL, pencarian DNS, pemeriksaan autentikasi, atau analisis reputasi domain yang dilakukan secara real-time. Temuan mewakili penilaian analitis berbasis bukti.',
    btn_new_from_result: 'Investigasi Baru',

    // Validation errors
    err_sender_name:  'Nama pengirim wajib diisi.',
    err_sender_email: 'Alamat email pengirim wajib diisi.',
    err_subject:      'Subjek email wajib diisi.',
    err_email_body:   'Isi email wajib diisi.',

    // History page
    hist_title:    'Riwayat Investigasi',
    hist_subtitle: 'Tinjau dan kelola laporan investigasi sebelumnya',
    btn_clear_all: 'Hapus Semua Riwayat',
    hist_empty:    'Tidak ada riwayat investigasi ditemukan.',
    hist_start_btn:'Mulai Investigasi Pertama',
    hist_col_time:  'Waktu',
    hist_col_sender:'Pengirim',
    hist_col_subject:'Subjek',
    hist_col_risk:  'Risiko',
    hist_col_conf:  'Keyakinan',
    hist_col_class: 'Klasifikasi',
    hist_col_actions:'Tindakan',
    hist_view_btn:  'Lihat',
    hist_delete_btn:'Hapus',
    confirm_delete: 'Hapus catatan investigasi ini?',
    confirm_clear_all: 'Hapus semua riwayat investigasi? Tindakan ini tidak dapat dibatalkan.',

    // Confidence badge prefix
    confidence_prefix: 'Keyakinan:',

    // About page
    about_title:    'Tentang PhishGuard AI',
    about_subtitle: 'Proyek Capstone IBM SkillsBuild',
    about_overview_title: 'Ikhtisar Aplikasi',
    about_overview_p1: 'PhishGuard AI — AI Phishing Email Investigator adalah aplikasi web keamanan siber profesional yang membantu pengguna menginvestigasi email mencurigakan, mengidentifikasi indikator phishing potensial, dan menghasilkan laporan investigasi keamanan terstruktur.',
    about_overview_p2: 'Aplikasi ini dibangun sebagai Proyek Capstone IBM SkillsBuild, menggabungkan pengembangan web modern dengan analisis keamanan siber berbasis AI untuk mendemonstrasikan keahlian rekayasa perangkat lunak full-stack dan keamanan siber yang praktis.',
    about_objectives_title: 'Tujuan Proyek',
    about_obj_1: 'Menyediakan analisis ancaman email berbasis AI yang dapat diakses oleh pengguna non-teknis',
    about_obj_2: 'Mengidentifikasi indikator phishing melalui investigasi terstruktur berbasis bukti',
    about_obj_3: 'Menghasilkan laporan keamanan profesional dengan penilaian risiko dan keyakinan',
    about_obj_4: 'Mendemonstrasikan arsitektur aplikasi web full-stack yang aman',
    about_obj_5: 'Menerapkan pengetahuan keamanan siber dan AI IBM SkillsBuild pada alat dunia nyata',
    about_caps_title: 'Kemampuan Investigasi',
    about_cap1_title: 'Analisis Identitas Pengirim',
    about_cap1_desc:  'Memeriksa nama tampilan, alamat email, dan karakteristik domain untuk indikator spoofing.',
    about_cap2_title: 'Deteksi Rekayasa Sosial',
    about_cap2_desc:  'Mengidentifikasi taktik urgensi, peniruan identitas, permintaan kredensial, dan manipulasi psikologis.',
    about_cap3_title: 'Analisis URL & Domain',
    about_cap3_desc:  'Menganalisis struktur URL, domain crafting, typosquatting, dan pola path mencurigakan.',
    about_cap4_title: 'Analisis Autentikasi',
    about_cap4_desc:  'Mengevaluasi hasil SPF, DKIM, dan DMARC serta menjelaskan implikasi keamanannya.',
    about_cap5_title: 'Penilaian Risiko',
    about_cap5_desc:  'Menetapkan tingkat risiko (RENDAH/SEDANG/TINGGI/KRITIS) dan keyakinan secara terpisah dengan penalaran berbasis bukti.',
    about_cap6_title: 'Pelaporan Terstruktur',
    about_cap6_desc:  'Menghasilkan laporan investigasi 12 bagian yang membedakan observasi terkonfirmasi, indikator, dan asumsi belum terverifikasi.',
    about_stack_title: 'Teknologi yang Digunakan',
    about_stack_frontend: 'HTML5, CSS3, Vanilla JavaScript',
    about_stack_backend:  'Node.js, Express.js',
    about_stack_ai:       'API Chat Completions kompatibel OpenAI',
    about_stack_storage:  'localStorage browser (riwayat investigasi)',
    about_stack_security: 'Validasi input, sanitasi, variabel lingkungan',
    about_limits_title: 'Keterbatasan Sistem',
    about_limit_1: 'Analisis didasarkan hanya pada informasi yang dikirimkan oleh pengguna. Tidak ada DNS real-time, pemindaian URL, atau pemeriksaan reputasi domain yang dilakukan.',
    about_limit_2: 'URL hanya dianalisis secara struktural. Aplikasi tidak pernah membuka, menelusuri, atau mengeksekusi URL yang dikirimkan.',
    about_limit_3: 'Hasil investigasi bergantung pada akurasi dan kelengkapan data email yang dikirimkan.',
    about_limit_4: 'Analisis AI bersifat probabilistik dan berbasis bukti. Laporan adalah penilaian investigatif, bukan penetapan pasti apakah email berbahaya atau sah.',
    about_limit_5: 'Riwayat investigasi disimpan di localStorage browser dan bersifat spesifik perangkat.',
    about_limit_6: 'Analisis AI memerlukan konfigurasi kunci API yang valid. Tanpanya, fitur analisis tidak tersedia.',

    // Translation state
    translating_title:    'Menerjemahkan Laporan',
    translating_subtitle: 'Menerjemahkan laporan ke bahasa yang dipilih...',
    error_translate_title: 'Terjemahan Gagal',
    error_translate_msg:   'Gagal menerjemahkan laporan. Laporan asli tetap ditampilkan.',
  },

  en: {
    // Navigation
    nav_dashboard:   'Dashboard',
    nav_investigate: 'Investigate',
    nav_history:     'History',
    nav_about:       'About',

    // Topbar
    topbar_new_investigation: 'New Investigation',
    topbar_title_dashboard:   'Dashboard',
    topbar_title_investigate: 'Investigate',
    topbar_title_history:     'Investigation History',
    topbar_title_about:       'About',

    // API Status
    status_checking:        'Checking...',
    status_connected:       'API Connected',
    status_not_configured:  'API Not Configured',
    status_offline:         'Server Offline',

    // Language selector
    lang_label: 'Language',
    lang_id:    'Bahasa Indonesia',
    lang_en:    'English',

    // Dashboard
    dash_title:    'Investigation Dashboard',
    dash_subtitle: 'AI-powered phishing threat analysis and email security investigation',
    dash_new_btn:  'New Investigation',
    stat_total:    'Total Investigated',
    stat_high:     'HIGH / CRITICAL Risk',
    stat_medium:   'MEDIUM Risk',
    stat_low:      'LOW Risk',
    recent_title:  'Recent Investigation Activity',
    recent_records_1: 'record',
    recent_records_n: 'records',
    recent_col_sender:  'Sender',
    recent_col_subject: 'Subject',
    recent_col_risk:    'Risk Level',
    recent_col_class:   'Classification',
    recent_col_date:    'Date',
    recent_col_action:  'Action',
    recent_view_btn:    'View',
    recent_empty:       'No investigations yet. Start your first investigation to see activity here.',
    recent_start_btn:   'Start Investigation',

    // API Warning Banner
    api_warning_title: 'API Not Configured',
    api_warning_body:  'AI analysis is unavailable. Copy',
    api_warning_body2: 'to',
    api_warning_body3: 'and set your',
    api_warning_body4: 'to enable investigations.',

    // Investigate page
    inv_title:    'Email Investigation',
    inv_subtitle: 'Submit email details for AI-powered phishing analysis',
    inv_form_card_title:   'Email Information',
    inv_required_badge:    'Required fields marked *',
    inv_section_sender:    'Sender Details',
    inv_label_sender_name: 'Sender Name *',
    inv_ph_sender_name:    'e.g. Security Team',
    inv_label_sender_email:'Sender Email Address *',
    inv_ph_sender_email:   'e.g. security@example.com',
    inv_label_subject:     'Email Subject *',
    inv_ph_subject:        'e.g. Urgent! Your Account Will Be Suspended',
    inv_section_message:   'Message Content',
    inv_label_body:        'Email Body *',
    inv_ph_body:           'Paste the full email body text here...',
    inv_char_count:        '/ 10,000 characters',
    inv_label_url:         'URL / Link',
    inv_optional:          '(optional)',
    inv_ph_url:            'Paste suspicious URL as plain text — do not click',
    inv_hint_url:          'Paste the URL as plain text. It will be analyzed structurally only.',
    inv_section_auth:      'Authentication & Headers',
    inv_label_spf:         'SPF Result',
    inv_label_dkim:        'DKIM Result',
    inv_label_dmarc:       'DMARC Result',
    inv_opt_not_provided:  'Not provided',
    inv_label_headers:     'Raw Email Headers',
    inv_ph_headers:        'Paste raw email headers here...',
    inv_hint_headers:      'From: / Reply-To: / Received: headers and authentication results.',
    btn_reset:             'Reset Form',
    btn_analyze:           'Analyze Email',
    btn_analyzing:         'Analyzing...',

    // Loading / Error states
    loading_title:    'Analyzing Email',
    loading_subtitle: 'AI investigation in progress. This may take up to 30 seconds.',
    error_default_title: 'Analysis Failed',
    error_connection_title: 'Connection Error',
    error_connection_msg: 'Cannot connect to the server. Make sure the backend is running on port 3000.',
    error_server_msg: 'Server error ({status}). Please try again.',
    btn_retry: 'Try Again',

    // Results: Risk Banner labels
    risk_label:       'RISK LEVEL',
    confidence_label: 'CONFIDENCE',

    // Results: Section headings
    result_sec1:  '1. Executive Summary',
    result_sec2:  '2. Email Information',
    result_sec3:  '3. Sender Identity Analysis',
    result_sec4:  '4. Social Engineering Detection',
    result_sec5:  '5. URL and Domain Analysis',
    result_sec6:  '6. Email Header & Authentication Analysis',
    result_sec7:  '7. Suspicious Indicators',
    result_sec8:  '8. Evidence Analysis',
    result_sec910:'9–10. Threat Classification & Risk Assessment',
    result_sec11: '11. Recommended Actions',
    result_sec12: '12. Investigation Limitations',

    // Results: Email info table labels
    info_sender_name:  'Sender Name',
    info_sender_email: 'Sender Email',
    info_sender_domain:'Sender Domain',
    info_subject:      'Subject',
    info_urls:         'URLs Provided',
    info_headers:      'Headers',
    info_spf:          'SPF',
    info_dkim:         'DKIM',
    info_dmarc:        'DMARC',
    info_none:         'None',
    info_not_provided: 'Not provided',

    // Results: Evidence sections
    evidence_confirmed:   '✅ Confirmed Observations',
    evidence_suspicious:  '⚠️ Suspicious Indicators',
    evidence_unverified:  '❓ Unverified Assumptions',
    evidence_no_items:    'No items in this category.',

    // Results: Indicators
    indicator_category_prefix: 'Category:',

    // Results: Classification block
    classification_label:   'Threat Classification',
    risk_level_label:       'Risk Level',
    confidence_level_label: 'Confidence Level',
    no_explanation:         'No explanation provided.',

    // Results: Empty lists
    no_indicators_msg: 'No significant suspicious indicators were identified from the available information.',
    no_items_provided: 'No items provided.',

    // Results: Modal
    modal_title:               'Investigation Report',
    modal_exec_summary:        'Executive Summary',
    modal_sender_analysis:     'Sender Identity Analysis',
    modal_social_engineering:  'Social Engineering Detection',
    modal_suspicious_indicators: 'Suspicious Indicators',
    modal_risk_explanation:    'Risk Explanation',
    modal_recommended_actions: 'Recommended Actions',
    modal_no_data:             'No result data available.',

    // Results: Report footer
    report_footer: 'This report was generated by AI Phishing Email Investigator. No real-time external verification, URL scanning, DNS lookup, authentication check, or domain reputation analysis was performed. Findings represent an evidence-based analytical assessment.',
    btn_new_from_result: 'New Investigation',

    // Validation errors
    err_sender_name:  'Sender name is required.',
    err_sender_email: 'Sender email address is required.',
    err_subject:      'Email subject is required.',
    err_email_body:   'Email body is required.',

    // History page
    hist_title:    'Investigation History',
    hist_subtitle: 'Review and manage previous investigation reports',
    btn_clear_all: 'Clear All History',
    hist_empty:    'No investigation history found.',
    hist_start_btn:'Start First Investigation',
    hist_col_time:  'Timestamp',
    hist_col_sender:'Sender',
    hist_col_subject:'Subject',
    hist_col_risk:  'Risk',
    hist_col_conf:  'Confidence',
    hist_col_class: 'Classification',
    hist_col_actions:'Actions',
    hist_view_btn:  'View',
    hist_delete_btn:'Delete',
    confirm_delete: 'Delete this investigation record?',
    confirm_clear_all: 'Clear all investigation history? This cannot be undone.',

    // Confidence badge prefix
    confidence_prefix: 'Confidence:',

    // About page
    about_title:    'About PhishGuard AI',
    about_subtitle: 'IBM SkillsBuild Capstone Project',
    about_overview_title: 'Application Overview',
    about_overview_p1: 'PhishGuard AI — AI Phishing Email Investigator is a professional cybersecurity web application that helps users investigate suspicious emails, identify potential phishing indicators, and generate structured security investigation reports.',
    about_overview_p2: 'The application is built as the IBM SkillsBuild Capstone Project, combining modern web development with AI-powered cybersecurity analysis to demonstrate practical full-stack engineering and cybersecurity expertise.',
    about_objectives_title: 'Project Objectives',
    about_obj_1: 'Provide AI-powered email threat analysis accessible to non-technical users',
    about_obj_2: 'Identify phishing indicators through structured, evidence-based investigation',
    about_obj_3: 'Generate professional security reports with risk and confidence assessments',
    about_obj_4: 'Demonstrate secure full-stack web application architecture',
    about_obj_5: 'Apply IBM SkillsBuild cybersecurity and AI knowledge to a real-world tool',
    about_caps_title: 'Investigation Capabilities',
    about_cap1_title: 'Sender Identity Analysis',
    about_cap1_desc:  'Examines display names, email addresses, and domain characteristics for spoofing indicators.',
    about_cap2_title: 'Social Engineering Detection',
    about_cap2_desc:  'Identifies urgency tactics, impersonation, credential requests, and psychological manipulation.',
    about_cap3_title: 'URL & Domain Analysis',
    about_cap3_desc:  'Analyzes URL structure, domain crafting, typosquatting, and suspicious path patterns.',
    about_cap4_title: 'Authentication Analysis',
    about_cap4_desc:  'Evaluates SPF, DKIM, and DMARC results and explains their security implications.',
    about_cap5_title: 'Risk Assessment',
    about_cap5_desc:  'Assigns separate risk (LOW/MEDIUM/HIGH/CRITICAL) and confidence levels with evidence-based reasoning.',
    about_cap6_title: 'Structured Reporting',
    about_cap6_desc:  'Generates 12-section investigation reports distinguishing confirmed observations, indicators, and unverified assumptions.',
    about_stack_title:    'Technology Stack',
    about_stack_frontend: 'HTML5, CSS3, Vanilla JavaScript',
    about_stack_backend:  'Node.js, Express.js',
    about_stack_ai:       'OpenAI-compatible Chat Completions API',
    about_stack_storage:  'Browser localStorage (investigation history)',
    about_stack_security: 'Input validation, sanitization, environment variables',
    about_limits_title: 'System Limitations',
    about_limit_1: 'Analysis is based solely on information submitted by the user. No real-time DNS, URL scanning, or domain reputation checks are performed.',
    about_limit_2: 'URLs are analyzed structurally only. The application never opens, browses, or executes submitted URLs.',
    about_limit_3: 'Investigation results depend on the accuracy and completeness of submitted email data.',
    about_limit_4: 'AI analysis is probabilistic and evidence-based. Reports are investigative assessments, not guaranteed determinations of malicious or legitimate intent.',
    about_limit_5: 'Investigation history is stored in browser localStorage and is device-specific.',
    about_limit_6: 'AI analysis requires a valid API key configuration. Without it, the analysis feature is unavailable.',

    // Translation state
    translating_title:    'Translating Report',
    translating_subtitle: 'Translating the report into the selected language...',
    error_translate_title: 'Translation Failed',
    error_translate_msg:   'Failed to translate the report. The original report is still displayed.',
  }
};

// ============================================================
// Language State
// ============================================================

/** Currently active language code: 'id' | 'en' */
let currentLang = localStorage.getItem(LANG_KEY) || 'id';

/** Translate a key using the current language. Falls back to key name. */
function t(key) {
  return (TRANSLATIONS[currentLang] && TRANSLATIONS[currentLang][key]) ||
         (TRANSLATIONS['en'] && TRANSLATIONS['en'][key]) ||
         key;
}

/** Persist language and apply all translations to the DOM */
function setLanguage(lang) {
  if (!TRANSLATIONS[lang]) return;
  currentLang = lang;
  localStorage.setItem(LANG_KEY, lang);
  document.documentElement.lang = lang;
  applyTranslations();
}

/**
 * Apply translations to all elements with data-i18n, data-i18n-placeholder,
 * and data-i18n-title attributes. Also refresh dynamic content.
 */
function applyTranslations() {
  // Static text content
  document.querySelectorAll('[data-i18n]').forEach(el => {
    el.textContent = t(el.dataset.i18n);
  });
  // Input placeholders
  document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
    el.placeholder = t(el.dataset.i18nPlaceholder);
  });
  // Title attributes
  document.querySelectorAll('[data-i18n-title]').forEach(el => {
    el.title = t(el.dataset.i18nTitle);
  });

  // Update the language selector to show current selection
  const selector = $('langSelector');
  if (selector) selector.value = currentLang;

  // Refresh topbar title for current page
  const titleKeys = {
    dashboard:   'topbar_title_dashboard',
    investigate: 'topbar_title_investigate',
    history:     'topbar_title_history',
    about:       'topbar_title_about',
  };
  setText('topbarTitle', t(titleKeys[currentPage] || 'topbar_title_dashboard'));

  // Refresh any already-rendered dynamic content
  if (currentPage === 'dashboard')   refreshDashboard();
  if (currentPage === 'history')     refreshHistory();
  if (currentPage === 'investigate') updateCharCount();

  // If a result is on screen, re-render section headings in new language.
  // Note: actual AI-generated text content is NOT re-translated here —
  // translation is triggered by the language selector handler below.
  if ($('investigationResults')?.style.display !== 'none' && currentResult) {
    renderResults(currentResult);
  }
}

// ============================================================
// State
// ============================================================
let currentPage           = 'dashboard';
let currentResult         = null;
let currentOriginalResult = null;   // stores the original-language result for translation switching
let lastFormData          = null;   // stores the last submitted form data for retry functionality
let isAnalyzing           = false;
let isTranslating         = false;

// ============================================================
// DOM Helpers
// ============================================================
const $ = (id) => document.getElementById(id);

function el(tag, className, text) {
  const elem = document.createElement(tag);
  if (className) elem.className = className;
  if (text !== undefined) elem.textContent = text;
  return elem;
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function setText(id, text) {
  const elem = $(id);
  if (elem) elem.textContent = text || '';
}

function setHtml(id, html) {
  const elem = $(id);
  if (elem) elem.innerHTML = html;
}

// ============================================================
// Local Storage — Investigation History
// ============================================================

function loadHistory() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}

function saveToHistory(formData, result) {
  try {
    const history = loadHistory();
    const record = {
      id: Date.now().toString(),
      timestamp: new Date().toISOString(),
      senderName:  formData.senderName,
      senderEmail: formData.senderEmail,
      subject:     formData.subject,
      riskLevel:        result.riskLevel,
      confidenceLevel:  result.confidenceLevel,
      threatClassification: result.threatClassification,
      result: result,
    };
    history.unshift(record);
    if (history.length > MAX_HISTORY) history.length = MAX_HISTORY;
    localStorage.setItem(STORAGE_KEY, JSON.stringify(history));
    return record;
  } catch (e) {
    // localStorage full or unavailable — silently skip history save
    console.warn('Could not save to history (storage unavailable or full):', e.message);
    return null;
  }
}

function deleteHistoryRecord(id) {
  const history = loadHistory().filter(r => r.id !== id);
  localStorage.setItem(STORAGE_KEY, JSON.stringify(history));
}

function clearAllHistory() {
  localStorage.removeItem(STORAGE_KEY);
}

// ============================================================
// Navigation
// ============================================================

function navigateTo(page) {
  document.querySelectorAll('.page').forEach(p => p.style.display = 'none');
  document.querySelectorAll('.nav-link').forEach(link => {
    link.classList.toggle('active', link.dataset.page === page);
  });

  const pageEl = $(`page-${page}`);
  if (pageEl) pageEl.style.display = '';

  currentPage = page;

  const titleKeys = {
    dashboard:   'topbar_title_dashboard',
    investigate: 'topbar_title_investigate',
    history:     'topbar_title_history',
    about:       'topbar_title_about',
  };
  setText('topbarTitle', t(titleKeys[page] || 'topbar_title_dashboard'));

  if (page === 'dashboard')   refreshDashboard();
  if (page === 'history')     refreshHistory();

  closeMobileSidebar();
}

// ============================================================
// Sidebar
// ============================================================

function openMobileSidebar() {
  $('sidebar').classList.add('mobile-open');
  $('sidebarOverlay').classList.add('active');
  document.body.style.overflow = 'hidden';
}

function closeMobileSidebar() {
  $('sidebar').classList.remove('mobile-open');
  $('sidebarOverlay').classList.remove('active');
  document.body.style.overflow = '';
}

// ============================================================
// API Health Check
// ============================================================

async function checkApiHealth() {
  const dot    = $('statusDot');
  const text   = $('statusText');
  const banner = $('apiWarningBanner');

  try {
    const res = await fetch(HEALTH_ENDPOINT);
    if (!res.ok) throw new Error('Server not reachable');
    const data = await res.json();

    if (data.apiConfigured) {
      dot.className    = 'status-dot online';
      text.textContent = t('status_connected');
      if (banner) banner.style.display = 'none';
    } else {
      dot.className    = 'status-dot warning';
      text.textContent = t('status_not_configured');
      if (banner) banner.style.display = 'flex';
    }
  } catch {
    dot.className    = 'status-dot offline';
    text.textContent = t('status_offline');
    if (banner) banner.style.display = 'flex';
  }
}

// ============================================================
// Dashboard
// ============================================================

function refreshDashboard() {
  const history = loadHistory();

  let high = 0, medium = 0, low = 0;
  history.forEach(r => {
    const level = (r.riskLevel || '').toUpperCase();
    if (level === 'HIGH' || level === 'CRITICAL') high++;
    else if (level === 'MEDIUM') medium++;
    else if (level === 'LOW') low++;
  });

  setText('statTotal',  history.length);
  setText('statHigh',   high);
  setText('statMedium', medium);
  setText('statLow',    low);

  const countKey = history.length === 1 ? 'recent_records_1' : 'recent_records_n';
  setText('recentCount', `${history.length} ${t(countKey)}`);

  const recent = history.slice(0, 10);
  const empty  = $('recentActivityEmpty');
  const table  = $('recentActivityTable');
  const tbody  = $('recentActivityBody');
  const thead  = table?.querySelector('thead tr');

  if (recent.length === 0) {
    empty.style.display = '';
    table.style.display = 'none';
  } else {
    empty.style.display = 'none';
    table.style.display = '';

    // Update table headers
    if (thead) {
      thead.innerHTML = `
        <th>${t('recent_col_sender')}</th>
        <th>${t('recent_col_subject')}</th>
        <th>${t('recent_col_risk')}</th>
        <th>${t('recent_col_class')}</th>
        <th>${t('recent_col_date')}</th>
        <th>${t('recent_col_action')}</th>
      `;
    }

    tbody.innerHTML = recent.map(r => `
      <tr>
        <td class="cell-primary">${escapeHtml(r.senderEmail)}</td>
        <td class="cell-primary">${escapeHtml(r.subject)}</td>
        <td>${riskBadgeHtml(r.riskLevel)}</td>
        <td>${escapeHtml(r.threatClassification || '—')}</td>
        <td style="white-space:nowrap;color:var(--text-muted);font-size:0.8rem">${formatTimestamp(r.timestamp)}</td>
        <td><button class="btn btn-ghost btn-xs" onclick="openHistoryRecord('${escapeHtml(r.id)}')">${t('recent_view_btn')}</button></td>
      </tr>
    `).join('');
  }
}

// ============================================================
// History Page
// ============================================================

function refreshHistory() {
  const history  = loadHistory();
  const empty    = $('historyEmpty');
  const wrapper  = $('historyTableWrapper');
  const tbody    = $('historyTableBody');
  const clearBtn = $('clearAllHistoryBtn');
  const thead    = wrapper?.querySelector('thead tr');

  if (history.length === 0) {
    empty.style.display    = '';
    wrapper.style.display  = 'none';
    clearBtn.style.display = 'none';
  } else {
    empty.style.display    = 'none';
    wrapper.style.display  = '';
    clearBtn.style.display = '';

    // Update table headers
    if (thead) {
      thead.innerHTML = `
        <th>${t('hist_col_time')}</th>
        <th>${t('hist_col_sender')}</th>
        <th>${t('hist_col_subject')}</th>
        <th>${t('hist_col_risk')}</th>
        <th>${t('hist_col_conf')}</th>
        <th>${t('hist_col_class')}</th>
        <th>${t('hist_col_actions')}</th>
      `;
    }

    tbody.innerHTML = history.map(r => `
      <tr>
        <td style="white-space:nowrap;color:var(--text-muted);font-size:0.8rem">${formatTimestamp(r.timestamp)}</td>
        <td class="cell-primary">${escapeHtml(r.senderEmail)}</td>
        <td class="cell-primary">${escapeHtml(r.subject)}</td>
        <td>${riskBadgeHtml(r.riskLevel)}</td>
        <td>${confidenceBadgeHtml(r.confidenceLevel)}</td>
        <td style="font-size:0.8rem;color:var(--text-secondary)">${escapeHtml(r.threatClassification || '—')}</td>
        <td>
          <div style="display:flex;gap:6px;">
            <button class="btn btn-ghost btn-xs" onclick="openHistoryRecord('${escapeHtml(r.id)}')">${t('hist_view_btn')}</button>
            <button class="btn btn-danger btn-xs" onclick="deleteRecord('${escapeHtml(r.id)}')">${t('hist_delete_btn')}</button>
          </div>
        </td>
      </tr>
    `).join('');
  }
}

function openHistoryRecord(id) {
  const history = loadHistory();
  const record  = history.find(r => r.id === id);
  if (!record) return;

  const modal = $('historyModal');
  const body  = $('modalBody');

  body.innerHTML = buildReportHtml(record.result, {
    senderName:  record.senderName,
    senderEmail: record.senderEmail,
    subject:     record.subject,
  });

  modal.style.display  = 'flex';
  document.body.style.overflow = 'hidden';
}

function deleteRecord(id) {
  if (!confirm(t('confirm_delete'))) return;
  deleteHistoryRecord(id);
  refreshHistory();
  refreshDashboard(); // Always refresh dashboard stats, regardless of current page
}

// ============================================================
// Investigation Form
// ============================================================

function validateForm(data) {
  const errors = {};
  if (!data.senderName.trim())  errors.senderName  = t('err_sender_name');
  if (!data.senderEmail.trim()) errors.senderEmail = t('err_sender_email');
  if (!data.subject.trim())     errors.subject     = t('err_subject');
  if (!data.emailBody.trim())   errors.emailBody   = t('err_email_body');
  return Object.keys(errors).length ? errors : null;
}

function showFormErrors(errors) {
  ['senderName', 'senderEmail', 'subject', 'emailBody'].forEach(field => {
    const input = document.querySelector(`[name="${field}"]`);
    const error = $(`error${field.charAt(0).toUpperCase() + field.slice(1)}`);
    if (input)  input.classList.toggle('is-error', !!errors[field]);
    if (error)  error.textContent = errors[field] || '';
  });
}

function clearFormErrors() {
  ['senderName', 'senderEmail', 'subject', 'emailBody'].forEach(field => {
    const input = document.querySelector(`[name="${field}"]`);
    const error = $(`error${field.charAt(0).toUpperCase() + field.slice(1)}`);
    if (input)  input.classList.remove('is-error');
    if (error)  error.textContent = '';
  });
}

function readFormData() {
  return {
    senderName:  ($('inputSenderName')?.value  || '').trim(),
    senderEmail: ($('inputSenderEmail')?.value || '').trim(),
    subject:     ($('inputSubject')?.value     || '').trim(),
    emailBody:   ($('inputEmailBody')?.value   || '').trim(),
    url:         ($('inputUrl')?.value         || '').trim(),
    rawHeaders:  ($('inputHeaders')?.value     || '').trim(),
    spfResult:   ($('inputSpf')?.value         || '').trim(),
    dkimResult:  ($('inputDkim')?.value        || '').trim(),
    dmarcResult: ($('inputDmarc')?.value       || '').trim(),
    language:    currentLang,  // Send selected language to backend
  };
}

function resetForm() {
  $('investigationForm')?.reset();
  clearFormErrors();
  updateCharCount();
  hideResults();
}

function updateCharCount() {
  const body  = $('inputEmailBody');
  const count = $('bodyCharCount');
  if (body && count) {
    count.textContent = `${body.value.length.toLocaleString()} ${t('inv_char_count')}`;
  }
}

// ============================================================
// Analysis — API Call
// ============================================================

async function runAnalysis(formData) {
  if (isAnalyzing) return;
  isAnalyzing = true;

  lastFormData = formData; // persist for retry functionality

  showLoading();

  try {
    const response = await fetch(API_ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(formData),
    });

    const data = await response.json();

    if (!response.ok || !data.success) {
      const msg = data?.error || t('error_server_msg').replace('{status}', response.status);
      showError(t('error_default_title'), msg);
      return;
    }

    // Guard: if user navigated away while request was in-flight, discard result
    if (currentPage !== 'investigate') {
      isAnalyzing = false;
      setAnalyzeButtonState(false);
      return;
    }

    currentResult         = data.result;
    currentOriginalResult = data.result;   // preserve original for translation switching
    saveToHistory(formData, data.result);
    renderResults(data.result);

  } catch (err) {
    if (currentPage === 'investigate') {
      const msg = err.message?.includes('fetch')
        ? t('error_connection_msg')
        : `${t('error_default_title')}: ${err.message}`;
      showError(t('error_connection_title'), msg);
    }
  } finally {
    isAnalyzing = false;
    setAnalyzeButtonState(false);
  }
}

// ============================================================
// Translation — language switch for existing result
// ============================================================

/**
 * Translate the current investigation result into the target language via the backend.
 * Uses the original-language result as the source to avoid round-trip translation corruption.
 * Shows loading state while in progress; falls back to the original result on error.
 */
async function translateResult(targetLang) {
  if (!currentOriginalResult || isTranslating || isAnalyzing) return;

  // If switching back to the original analysis language stored in the result, use it directly
  // (heuristic: check the original result's executiveSummary for the language the AI used)
  // We always translate from the original source to avoid corruption.

  isTranslating = true;

  // Show a lightweight "translating" loading overlay
  $('loadingState').style.display         = '';
  $('errorState').style.display           = 'none';
  $('investigationResults').style.display = 'none';
  setText('loadingTitle',    t('translating_title'));
  setText('loadingSubtitle', t('translating_subtitle'));

  try {
    const response = await fetch(TRANSLATE_ENDPOINT, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ result: currentOriginalResult, language: targetLang }),
    });

    const data = await response.json();

    if (!response.ok || !data.success) {
      // Translation failed — restore original result display
      showError(t('error_translate_title'), data?.error || t('error_translate_msg'));
      // After 3 seconds, fall back to showing the original result
      setTimeout(() => {
        currentResult = currentOriginalResult;
        renderResults(currentResult);
      }, 3000);
      return;
    }

    currentResult = data.result;
    renderResults(currentResult);

  } catch (err) {
    showError(t('error_translate_title'), t('error_translate_msg'));
    setTimeout(() => {
      currentResult = currentOriginalResult;
      renderResults(currentResult);
    }, 3000);
  } finally {
    isTranslating = false;
    // Reset loading title/subtitle back to analysis defaults for next use
    setText('loadingTitle',    t('loading_title'));
    setText('loadingSubtitle', t('loading_subtitle'));
  }
}

// ============================================================
// UI State Helpers
// ============================================================

function showLoading() {
  $('loadingState').style.display         = '';
  $('errorState').style.display           = 'none';
  $('investigationResults').style.display = 'none';
  setAnalyzeButtonState(true);
}

function hideResults() {
  $('loadingState').style.display         = 'none';
  $('errorState').style.display           = 'none';
  $('investigationResults').style.display = 'none';
}

function showError(title, message) {
  $('loadingState').style.display         = 'none';
  $('errorState').style.display           = '';
  $('investigationResults').style.display = 'none';
  setText('errorTitle', title);
  setText('errorMessage', message);
}

function setAnalyzeButtonState(loading) {
  const btn = $('analyzeBtn');
  if (!btn) return;
  btn.disabled = loading;
  btn.innerHTML = loading
    ? `<span class="spinner" style="width:14px;height:14px;border-width:2px;"></span> ${t('btn_analyzing')}`
    : `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg> ${t('btn_analyze')}`;
}

// ============================================================
// Result Rendering
// ============================================================

function renderResults(result) {
  $('loadingState').style.display         = 'none';
  $('errorState').style.display           = 'none';
  $('investigationResults').style.display = '';

  renderRiskBanner(result);

  setText('resultExecutiveSummary', result.executiveSummary || '');
  renderEmailInfoTable(result.emailInfo || {});

  setText('resultSenderAnalysis',     result.senderAnalysis || t('info_not_provided'));
  setText('resultSocialEngineering',  result.socialEngineeringAnalysis || t('info_not_provided'));
  setText('resultUrlAnalysis',        result.urlAnalysis || t('info_not_provided'));
  setText('resultHeaderAnalysis',     result.headerAnalysis || t('info_not_provided'));

  renderIndicators(result.suspiciousIndicators || []);
  renderEvidenceAnalysis(result.evidenceAnalysis || {});
  renderClassificationBlock(result);
  renderList('recommendedActions',     result.recommendedActions || [],     'action-list',     'action');
  renderList('investigationLimitations', result.investigationLimitations || [], 'limitation-list', 'limitation');

  // Update translated section headings in result cards
  const headings = [
    ['resultSec1',  'result_sec1'],
    ['resultSec2',  'result_sec2'],
    ['resultSec3',  'result_sec3'],
    ['resultSec4',  'result_sec4'],
    ['resultSec5',  'result_sec5'],
    ['resultSec6',  'result_sec6'],
    ['resultSec7',  'result_sec7'],
    ['resultSec8',  'result_sec8'],
    ['resultSec910','result_sec910'],
    ['resultSec11', 'result_sec11'],
    ['resultSec12', 'result_sec12'],
  ];
  headings.forEach(([id, key]) => setText(id, t(key)));

  // Report footer text
  setText('reportFooterText', t('report_footer'));

  $('investigationResults').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function renderRiskBanner(result) {
  const banner    = $('riskBanner');
  const riskEl    = $('riskValue');
  const confEl    = $('confidenceValue');
  const classifEl = $('threatClassificationBadge');

  const risk = (result.riskLevel || 'UNKNOWN').toUpperCase();
  const conf = (result.confidenceLevel || 'UNKNOWN').toUpperCase();

  riskEl.textContent = risk;
  riskEl.className   = `risk-value risk-${risk.toLowerCase()}`;

  confEl.textContent = conf;
  confEl.className   = `risk-value ${confidenceClass(conf)}`;

  classifEl.className   = `badge ${classificationBadgeClass(result.threatClassification)}`;
  classifEl.textContent = result.threatClassification || '—';

  // Update banner label text
  setText('riskBannerLabel',       t('risk_label'));
  setText('confidenceBannerLabel', t('confidence_label'));

  const borderColors = { CRITICAL: '#ff4444', HIGH: '#f85149', MEDIUM: '#e3b341', LOW: '#3fb950' };
  banner.style.borderLeftColor = borderColors[risk] || 'var(--border)';
  banner.style.borderLeftWidth = '4px';
}

function renderEmailInfoTable(info) {
  const rows = [
    [t('info_sender_name'),   info.senderName    || '—'],
    [t('info_sender_email'),  info.senderEmail   || '—'],
    [t('info_sender_domain'), info.senderDomain  || '—'],
    [t('info_subject'),       info.subject       || '—'],
    [t('info_urls'),          info.urlsProvided  || t('info_none')],
    [t('info_headers'),       info.headersProvided || t('info_not_provided')],
    ['SPF',                   info.spf           || t('info_not_provided')],
    ['DKIM',                  info.dkim          || t('info_not_provided')],
    ['DMARC',                 info.dmarc         || t('info_not_provided')],
  ];

  const html = rows.map(([label, value]) =>
    `<tr><td>${escapeHtml(label)}</td><td>${escapeHtml(value)}</td></tr>`
  ).join('');

  setHtml('emailInfoTable', html);
}

function renderIndicators(indicators) {
  const container = $('indicatorsContainer');
  const noMsg     = $('noIndicatorsMsg');

  if (!indicators || indicators.length === 0) {
    noMsg.style.display = '';
    noMsg.textContent   = t('no_indicators_msg');
    container.innerHTML = '';
    return;
  }

  noMsg.style.display = 'none';

  container.innerHTML = indicators.map(ind => `
    <div class="indicator-item">
      <div class="indicator-severity">
        <span class="severity-badge-${escapeHtml((ind.severity || 'LOW').toUpperCase())}">${escapeHtml(ind.severity || 'LOW')}</span>
      </div>
      <div class="indicator-body">
        <div class="indicator-title">${escapeHtml(ind.indicator || '')}</div>
        <div class="indicator-category">${t('indicator_category_prefix')} ${escapeHtml(ind.category || '—')}</div>
        <div class="indicator-assessment">${escapeHtml(ind.assessment || '')}</div>
      </div>
    </div>
  `).join('');
}

function renderEvidenceAnalysis(evidence) {
  const grid = $('evidenceGrid');

  const sections = [
    { key: 'confirmedObservations', label: t('evidence_confirmed'),  cssClass: 'evidence-confirmed',  items: evidence.confirmedObservations || [] },
    { key: 'suspiciousIndicators',  label: t('evidence_suspicious'), cssClass: 'evidence-suspicious', items: evidence.suspiciousIndicators  || [] },
    { key: 'unverifiedAssumptions', label: t('evidence_unverified'), cssClass: 'evidence-unverified', items: evidence.unverifiedAssumptions  || [] },
  ];

  grid.innerHTML = sections.map(s => `
    <div class="evidence-section">
      <div class="evidence-section-title ${escapeHtml(s.cssClass)}">${s.label}</div>
      <ul class="evidence-list">
        ${s.items.length
          ? s.items.map(item => `<li>${escapeHtml(item)}</li>`).join('')
          : `<li style="color:var(--text-muted)">${t('evidence_no_items')}</li>`
        }
      </ul>
    </div>
  `).join('');
}

function renderClassificationBlock(result) {
  const block = $('classificationBlock');
  const expl  = $('riskExplanation');

  block.innerHTML = `
    <div>
      <div class="classification-label">${t('classification_label')}</div>
      <div class="classification-value">${escapeHtml(result.threatClassification || '—')}</div>
    </div>
    <div style="margin-left:auto;display:flex;gap:10px;align-items:center;flex-wrap:wrap;">
      <div>${riskBadgeHtml(result.riskLevel)}</div>
      <div>${confidenceBadgeHtml(result.confidenceLevel)}</div>
    </div>
  `;

  expl.innerHTML = `
    <div class="risk-explanation-block">
      <h4>${t('risk_level_label')} — ${escapeHtml(result.riskLevel || '—')}</h4>
      <p>${escapeHtml(result.riskExplanation || t('no_explanation'))}</p>
    </div>
    <div class="risk-explanation-block" style="margin-top:14px;">
      <h4>${t('confidence_level_label')} — ${escapeHtml(result.confidenceLevel || '—')}</h4>
      <p>${escapeHtml(result.confidenceExplanation || t('no_explanation'))}</p>
    </div>
  `;
}

function renderList(containerId, items, listClass, type) {
  const container = $(containerId);
  if (!container) return;

  if (!items || items.length === 0) {
    container.innerHTML = `<li style="color:var(--text-muted);font-size:0.875rem;list-style:none;padding:10px 14px;background:var(--bg-elevated);border-radius:var(--radius)">${t('no_items_provided')}</li>`;
    return;
  }

  if (type === 'action') {
    container.innerHTML = items.map((item, i) => {
      // Strip any leading numbering that the AI may have included (e.g. "1. ", "2) ")
      const clean = String(item).replace(/^\d+[\.\)]\s*/, '');
      return `<li><span class="action-number">${i + 1}.</span> ${escapeHtml(clean)}</li>`;
    }).join('');
  } else {
    container.innerHTML = items.map(item =>
      `<li>${escapeHtml(item)}</li>`
    ).join('');
  }
}

// ============================================================
// Report HTML Builder (for history modal)
// ============================================================

function buildReportHtml(result, meta) {
  if (!result) return `<p style="color:var(--text-muted)">${t('modal_no_data')}</p>`;

  const r = result;

  return `
    <div>
      ${riskBadgeHtml(r.riskLevel)} &nbsp; ${confidenceBadgeHtml(r.confidenceLevel)}
      <span style="margin-left:12px;font-size:0.85rem;color:var(--text-secondary)">${escapeHtml(r.threatClassification || '')}</span>
    </div>

    <div style="margin:16px 0;padding:12px 16px;background:var(--bg-elevated);border-radius:var(--radius);">
      <div style="font-size:0.75rem;text-transform:uppercase;letter-spacing:0.05em;color:var(--text-muted);margin-bottom:6px;">${t('modal_exec_summary')}</div>
      <p style="font-size:0.875rem;color:var(--text-secondary);line-height:1.6;">${escapeHtml(r.executiveSummary || '')}</p>
    </div>

    <div style="margin-bottom:16px;">
      <div style="font-size:0.75rem;text-transform:uppercase;letter-spacing:0.05em;color:var(--text-muted);margin-bottom:8px;font-weight:700;">${t('modal_sender_analysis')}</div>
      <p style="font-size:0.85rem;color:var(--text-secondary);line-height:1.6;white-space:pre-wrap;">${escapeHtml(r.senderAnalysis || '')}</p>
    </div>

    <div style="margin-bottom:16px;">
      <div style="font-size:0.75rem;text-transform:uppercase;letter-spacing:0.05em;color:var(--text-muted);margin-bottom:8px;font-weight:700;">${t('modal_social_engineering')}</div>
      <p style="font-size:0.85rem;color:var(--text-secondary);line-height:1.6;white-space:pre-wrap;">${escapeHtml(r.socialEngineeringAnalysis || '')}</p>
    </div>

    ${(r.suspiciousIndicators || []).length > 0 ? `
    <div style="margin-bottom:16px;">
      <div style="font-size:0.75rem;text-transform:uppercase;letter-spacing:0.05em;color:var(--text-muted);margin-bottom:8px;font-weight:700;">${t('modal_suspicious_indicators')}</div>
      ${(r.suspiciousIndicators || []).map(ind => `
        <div style="padding:10px 12px;background:var(--bg-elevated);border-radius:var(--radius);margin-bottom:6px;">
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;">
            <span class="severity-badge-${escapeHtml((ind.severity || 'LOW').toUpperCase())}">${escapeHtml(ind.severity || 'LOW')}</span>
            <strong style="font-size:0.875rem;color:var(--text-primary);">${escapeHtml(ind.indicator || '')}</strong>
          </div>
          <div style="font-size:0.8rem;color:var(--text-muted);">${t('indicator_category_prefix')} ${escapeHtml(ind.category || '—')}</div>
          <div style="font-size:0.85rem;color:var(--text-secondary);margin-top:4px;">${escapeHtml(ind.assessment || '')}</div>
        </div>
      `).join('')}
    </div>
    ` : ''}

    <div style="margin-bottom:16px;">
      <div style="font-size:0.75rem;text-transform:uppercase;letter-spacing:0.05em;color:var(--text-muted);margin-bottom:8px;font-weight:700;">${t('modal_risk_explanation')}</div>
      <p style="font-size:0.85rem;color:var(--text-secondary);line-height:1.6;">${escapeHtml(r.riskExplanation || '')}</p>
    </div>

    <div>
      <div style="font-size:0.75rem;text-transform:uppercase;letter-spacing:0.05em;color:var(--text-muted);margin-bottom:8px;font-weight:700;">${t('modal_recommended_actions')}</div>
      <ol style="padding-left:0;list-style:none;display:flex;flex-direction:column;gap:6px;">
        ${(r.recommendedActions || []).map((item, i) => `
          <li style="font-size:0.85rem;color:var(--text-secondary);padding:8px 12px;background:var(--bg-elevated);border-radius:var(--radius);border-left:3px solid var(--accent);display:flex;gap:10px;">
            <span style="font-weight:700;color:var(--accent);flex-shrink:0;">${i + 1}.</span> ${escapeHtml(item)}
          </li>
        `).join('')}
      </ol>
    </div>
  `;
}

// ============================================================
// Badge Helpers
// ============================================================

function riskBadgeHtml(level) {
  const l = (level || 'UNKNOWN').toUpperCase();
  const cls = {
    CRITICAL: 'badge-risk-critical',
    HIGH:     'badge-risk-high',
    MEDIUM:   'badge-risk-medium',
    LOW:      'badge-risk-low',
  }[l] || 'badge-risk-unknown';
  return `<span class="badge ${cls}">${escapeHtml(l)}</span>`;
}

function confidenceBadgeHtml(level) {
  const l   = (level || 'UNKNOWN').toUpperCase();
  const cls = { HIGH: 'badge-conf-high', MEDIUM: 'badge-conf-medium', LOW: 'badge-conf-low' }[l] || 'badge-conf-low';
  return `<span class="badge ${cls}">${t('confidence_prefix')} ${escapeHtml(l)}</span>`;
}

function confidenceClass(level) {
  const l = (level || '').toUpperCase();
  return { HIGH: 'risk-low', MEDIUM: 'risk-medium', LOW: 'risk-unknown' }[l] || 'risk-unknown';
}

function classificationBadgeClass(classification) {
  if (!classification) return 'badge-muted';
  if (classification.includes('Potential Phishing') || classification.includes('Potensi Phishing')) return 'badge-red';
  if (classification.includes('Suspicious') || classification.includes('Mencurigakan'))             return 'badge-orange';
  if (classification.includes('No Significant') || classification.includes('Tidak Ada'))            return 'badge-green';
  return 'badge-muted';
}

// ============================================================
// Timestamp Formatter
// ============================================================

function formatTimestamp(iso) {
  try {
    const d = new Date(iso);
    const locale = currentLang === 'id' ? 'id-ID' : 'en-US';
    return d.toLocaleString(locale, {
      year: 'numeric', month: 'short', day: 'numeric',
      hour: '2-digit', minute: '2-digit'
    });
  } catch {
    return iso || '—';
  }
}

// ============================================================
// About Page Dynamic Render
// ============================================================

function renderAboutPage() {
  // Uses data-i18n attributes — applyTranslations() handles them.
  // This function exists as a hook if future dynamic about content is needed.
}

// ============================================================
// Event Listeners
// ============================================================

document.addEventListener('DOMContentLoaded', () => {

  // ---- Language Selector ----
  const langSelector = $('langSelector');
  if (langSelector) {
    langSelector.value = currentLang;
    langSelector.addEventListener('change', (e) => {
      const newLang = e.target.value;
      setLanguage(newLang);
      checkApiHealth(); // Re-check to update status text in new language

      // If a result is currently displayed, translate it into the new language
      const resultsVisible = $('investigationResults')?.style.display !== 'none';
      if (resultsVisible && currentOriginalResult) {
        translateResult(newLang);
      }
    });
  }

  // ---- Navigation ----
  document.querySelectorAll('.nav-link').forEach(link => {
    link.addEventListener('click', (e) => {
      e.preventDefault();
      navigateTo(link.dataset.page);
    });
  });

  // ---- Sidebar toggle ----
  $('sidebarToggle')?.addEventListener('click', () => {
    if (window.innerWidth <= 768) openMobileSidebar();
  });

  // ---- Mobile menu button ----
  $('topbarMenuBtn')?.addEventListener('click', openMobileSidebar);

  // ---- Sidebar overlay close ----
  $('sidebarOverlay')?.addEventListener('click', closeMobileSidebar);

  // ---- New Investigation buttons ----
  ['dashNewInvestigation', 'topbarNewInvestigation', 'emptyStateNewInvestigation',
   'historyNewInvestigation', 'newInvestigationFromResult'].forEach(id => {
    $(id)?.addEventListener('click', () => {
      currentResult = null;
      currentOriginalResult = null;
      navigateTo('investigate');
      resetForm();
    });
  });

  // ---- Advanced section toggle ----
  $('advancedToggle')?.addEventListener('click', () => {
    const body    = $('advancedBody');
    const chevron = $('advancedChevron');
    const isOpen  = body.style.display !== 'none';
    body.style.display = isOpen ? 'none' : '';
    chevron.classList.toggle('open', !isOpen);
  });

  // ---- Email body character counter ----
  $('inputEmailBody')?.addEventListener('input', updateCharCount);

  // ---- Reset form ----
  $('resetFormBtn')?.addEventListener('click', resetForm);

  // ---- Error retry ----
  $('errorRetryBtn')?.addEventListener('click', () => {
    if (currentResult === null) hideResults();
  });

  // ---- Investigation form submit ----
  $('investigationForm')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    clearFormErrors();

    const data   = readFormData();
    const errors = validateForm(data);

    if (errors) {
      showFormErrors(errors);
      const firstErrorInput = document.querySelector('.form-input.is-error');
      if (firstErrorInput) firstErrorInput.scrollIntoView({ behavior: 'smooth', block: 'center' });
      return;
    }

    await runAnalysis(data);
  });

  // ---- History: clear all ----
  $('clearAllHistoryBtn')?.addEventListener('click', () => {
    if (!confirm(t('confirm_clear_all'))) return;
    clearAllHistory();
    refreshHistory();
    refreshDashboard();
  });

  // ---- History modal close ----
  $('modalClose')?.addEventListener('click', () => {
    $('historyModal').style.display = 'none';
    document.body.style.overflow = '';
  });

  $('historyModal')?.addEventListener('click', (e) => {
    if (e.target === $('historyModal')) {
      $('historyModal').style.display = 'none';
      document.body.style.overflow = '';
    }
  });

  // ---- Keyboard: close modal on Escape ----
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      const modal = $('historyModal');
      if (modal && modal.style.display !== 'none') {
        modal.style.display = 'none';
        document.body.style.overflow = '';
      }
      closeMobileSidebar();
    }
  });

  // ---- Initial load ----
  // Apply saved language first (sets all data-i18n text before navigation renders content)
  applyTranslations();
  checkApiHealth();
  navigateTo('dashboard');
  updateCharCount();
});
