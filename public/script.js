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
const THEME_KEY      = 'phishguard_theme';
const TRANSLATION_CACHE_KEY = 'phishguard_translation_cache_v2';
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
    theme_to_light: 'Beralih ke mode terang',
    theme_to_dark:  'Beralih ke mode gelap',

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
    api_warning_body:  'Analisis AI tidak tersedia. Buat file',
    api_warning_body2: '',
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
    about_stack_ai:       'Google Gemini API melalui package @google/genai',
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
    error_translate_msg:   'Gagal menerjemahkan laporan. Laporan asli tidak diubah; gunakan tombol untuk melihatnya.',
    error_translate_unavailable: 'Layanan Gemini sedang tidak tersedia. Silakan coba lagi nanti.',
    error_translate_rate_limit: 'Batas permintaan Gemini tercapai. Silakan tunggu dan coba lagi.',
    error_translate_auth: 'Autentikasi Gemini gagal. Periksa konfigurasi API.',
    error_translate_timeout: 'Permintaan terjemahan terlalu lama. Silakan coba lagi.',
    btn_show_original: 'Lihat laporan asli',
    translation_original_preserved: 'Laporan asli tetap tersimpan dan tidak diubah.',
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
    theme_to_light: 'Switch to light mode',
    theme_to_dark:  'Switch to dark mode',

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
    api_warning_body:  'AI analysis is unavailable. Create',
    api_warning_body2: '',
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
    about_stack_ai:       'Google Gemini API via the @google/genai package',
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
    error_translate_msg:   'Failed to translate the report. The original report is unchanged; use the button to view it.',
    error_translate_unavailable: 'Gemini service is temporarily unavailable. Please try again later.',
    error_translate_rate_limit: 'Gemini request limit reached. Please wait and try again.',
    error_translate_auth: 'Gemini authentication failed. Check the API configuration.',
    error_translate_timeout: 'The translation request timed out. Please try again.',
    btn_show_original: 'View original report',
    translation_original_preserved: 'The original report is preserved and has not been changed.',
  }
};

// ============================================================
// Language State
// ============================================================

/** Currently active language code: 'id' | 'en' */
let currentLang = localStorage.getItem(LANG_KEY) || 'id';

/** Apply the selected theme and keep the toggle state accessible. */
function applyTheme(theme) {
  const nextTheme = theme === 'light' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', nextTheme);
  try { localStorage.setItem(THEME_KEY, nextTheme); } catch (e) { /* storage may be unavailable */ }

  const toggle = $('themeToggle');
  if (toggle) {
    const isDark = nextTheme === 'dark';
    toggle.setAttribute('aria-label', t(isDark ? 'theme_to_light' : 'theme_to_dark'));
    toggle.setAttribute('title', t(isDark ? 'theme_to_light' : 'theme_to_dark'));
    toggle.dataset.theme = nextTheme;
    toggle.querySelector('.theme-icon-moon')?.toggleAttribute('hidden', isDark);
    toggle.querySelector('.theme-icon-sun')?.toggleAttribute('hidden', !isDark);
  }
}

function toggleTheme() {
  applyTheme(document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark');
}

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

  // Keep the theme control's accessible label and tooltip in the active language.
  const activeTheme = document.documentElement.getAttribute('data-theme') || 'dark';
  const themeToggle = $('themeToggle');
  if (themeToggle) {
    const key = activeTheme === 'dark' ? 'theme_to_light' : 'theme_to_dark';
    themeToggle.setAttribute('aria-label', t(key));
    themeToggle.setAttribute('title', t(key));
  }

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
let openReportRecordId    = null;
let openReportRenderToken = 0;
const translationRequests = new Map();

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
    const history = raw ? JSON.parse(raw) : [];
    if (!Array.isArray(history)) return [];

    // Backfill only metadata for legacy records. The original report object is
    // copied unchanged, so existing history remains fully backward compatible.
    let migrated = false;
    const normalized = history.map(record => {
      if (!record || record.sourceLanguage || record.language || !record.result) return record;
      const detected = detectReportLanguage(record.result);
      if (!detected) return record;
      migrated = true;
      return { ...record, sourceLanguage: detected };
    });
    if (migrated) {
      try { localStorage.setItem(STORAGE_KEY, JSON.stringify(normalized)); }
      catch (e) { console.warn('Could not migrate history language metadata:', e.message); }
    }
    return normalized;
  } catch {
    return [];
  }
}

function detectReportLanguage(result) {
  const text = [];
  const collect = value => {
    if (typeof value === 'string') text.push(value.toLowerCase());
    else if (Array.isArray(value)) value.forEach(collect);
    else if (value && typeof value === 'object') Object.values(value).forEach(collect);
  };
  collect(result);
  const sample = text.join(' ');
  const indonesianMarkers = [
    'investigasi', 'pengirim', 'tidak disediakan', 'ringkasan', 'tingkat risiko',
    'tindakan yang direkomendasikan', 'mencurigakan', 'berdasarkan', 'email ini'
  ];
  const englishMarkers = [
    'investigation', 'sender', 'not provided', 'executive summary', 'risk level',
    'recommended actions', 'suspicious', 'based on', 'this email'
  ];
  const idScore = indonesianMarkers.reduce((score, marker) => score + (sample.includes(marker) ? 1 : 0), 0);
  const enScore = englishMarkers.reduce((score, marker) => score + (sample.includes(marker) ? 1 : 0), 0);
  if (idScore === 0 && enScore === 0) return null;
  return idScore >= enScore ? 'id' : 'en';
}

function loadTranslationCache() {
  try {
    const raw = localStorage.getItem(TRANSLATION_CACHE_KEY);
    const cache = raw ? JSON.parse(raw) : {};
    return cache && typeof cache === 'object' ? cache : {};
  } catch {
    return {};
  }
}

function saveTranslationCache(cache) {
  try {
    localStorage.setItem(TRANSLATION_CACHE_KEY, JSON.stringify(cache));
  } catch (e) {
    console.warn('Could not save translation cache:', e.message);
  }
}

function getCachedTranslation(recordId, language) {
  return loadTranslationCache()[String(recordId)]?.[language] || null;
}

function cacheTranslation(recordId, language, result) {
  const cache = loadTranslationCache();
  const key = String(recordId);
  if (!cache[key] || typeof cache[key] !== 'object') cache[key] = {};
  cache[key][language] = result;
  saveTranslationCache(cache);
}

function saveToHistory(formData, result) {
  try {
    const history = loadHistory();
    const record = {
      id: Date.now().toString(),
      timestamp: new Date().toISOString(),
      sourceLanguage: currentLang,
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
        <td><button class="btn btn-ghost btn-xs" data-history-action="view" data-record-id="${escapeHtml(r.id)}">${t('recent_view_btn')}</button></td>
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
            <button class="btn btn-ghost btn-xs" data-history-action="view" data-record-id="${escapeHtml(r.id)}">${t('hist_view_btn')}</button>
            <button class="btn btn-danger btn-xs" data-history-action="delete" data-record-id="${escapeHtml(r.id)}">${t('hist_delete_btn')}</button>
          </div>
        </td>
      </tr>
    `).join('');
  }
}

function openHistoryRecord(id) {
  const recordId = String(id);
  const history = loadHistory();
  const record  = history.find(r => String(r.id) === recordId);
  if (!record) return;

  openReportRecordId = recordId;
  openReportRenderToken += 1;
  const modal = $('historyModal');
  modal.style.display  = 'flex';
  document.body.style.overflow = 'hidden';
  renderHistoryReport(record);
}

function historyReportMeta(record) {
  return {
    senderName: record.senderName,
    senderEmail: record.senderEmail,
    subject: record.subject,
  };
}

function renderReportLoading() {
  $('modalBody').innerHTML = `
    <div class="report-translation-state">
      <div class="spinner"></div>
      <h3>${escapeHtml(t('translating_title'))}</h3>
      <p>${escapeHtml(t('translating_subtitle'))}</p>
    </div>`;
}

function renderReportTranslationError(record, errorMessage) {
  $('modalBody').innerHTML = `
    <div class="report-translation-error" role="alert">
      <h3>${escapeHtml(t('error_translate_title'))}</h3>
      <p>${escapeHtml(errorMessage || t('error_translate_msg'))}</p>
      <button class="btn btn-primary btn-sm" data-history-action="retry-translation" data-record-id="${escapeHtml(record.id)}">
        ${escapeHtml(t('btn_retry'))}
      </button>
      <button class="btn btn-ghost btn-sm" data-history-action="show-original" data-record-id="${escapeHtml(record.id)}">
        ${escapeHtml(t('btn_show_original'))}
      </button>
    </div>
    <p class="report-translation-note">${escapeHtml(t('translation_original_preserved'))}</p>`;
}

function showOriginalHistoryReport(record) {
  $('modalBody').innerHTML = buildReportHtml(record.result, historyReportMeta(record));
}

function translateStoredReport(record, language) {
  const requestKey = `${record.id}:${language}`;
  if (translationRequests.has(requestKey)) return translationRequests.get(requestKey);

  const request = fetch(TRANSLATE_ENDPOINT, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ result: record.result, language }),
  }).then(async response => {
    const data = await response.json();
    if (!response.ok || !data.success || !data.result) {
      const error = new Error(data?.error || t('error_translate_msg'));
      error.type = data?.type || `HTTP_${response.status}`;
      throw error;
    }
    cacheTranslation(record.id, language, data.result);
    return data.result;
  }).finally(() => {
    translationRequests.delete(requestKey);
  });

  translationRequests.set(requestKey, request);
  return request;
}

async function renderHistoryReport(record) {
  const token = openReportRenderToken;
  const targetLanguage = currentLang;
  const cached = getCachedTranslation(record.id, targetLanguage);
  const sourceLanguage = record.sourceLanguage || record.language || detectReportLanguage(record.result);

  // New records carry their source language. Legacy records are translated once
  // per target language because their original language was not stored.
  if (cached) {
    $('modalBody').innerHTML = buildReportHtml(cached, historyReportMeta(record));
    return;
  }

  if (sourceLanguage === targetLanguage) {
    cacheTranslation(record.id, targetLanguage, record.result);
    $('modalBody').innerHTML = buildReportHtml(record.result, historyReportMeta(record));
    return;
  }

  renderReportLoading();
  try {
    const translated = await translateStoredReport(record, targetLanguage);
    if (token !== openReportRenderToken || openReportRecordId !== String(record.id)) return;
    $('modalBody').innerHTML = buildReportHtml(translated, historyReportMeta(record));
  } catch (err) {
    if (token !== openReportRenderToken || openReportRecordId !== String(record.id)) return;
    const errorKey = {
      RATE_LIMIT: 'error_translate_rate_limit',
      AUTH_ERROR: 'error_translate_auth',
      TIMEOUT: 'error_translate_timeout',
      SERVICE_ERROR: 'error_translate_unavailable',
      NETWORK_ERROR: 'error_translate_unavailable',
    }[err.type];
    renderReportTranslationError(record, errorKey ? t(errorKey) : t('error_translate_msg'));
  }
}

function refreshOpenHistoryReport() {
  if (!openReportRecordId) return;
  const record = loadHistory().find(r => String(r.id) === openReportRecordId);
  if (record) {
    openReportRenderToken += 1;
    renderHistoryReport(record);
  }
}

function closeHistoryModal() {
  openReportRenderToken += 1;
  openReportRecordId = null;
  $('historyModal').style.display = 'none';
  document.body.style.overflow = '';
}

function handleHistoryAction(event) {
  const button = event.target.closest('[data-history-action][data-record-id]');
  if (!button) return;
  const id = button.dataset.recordId;
  if (button.dataset.historyAction === 'view') openHistoryRecord(id);
  if (button.dataset.historyAction === 'delete') deleteRecord(id);
  if (button.dataset.historyAction === 'retry-translation') {
    const record = loadHistory().find(r => String(r.id) === String(id));
    if (record) {
      openReportRenderToken += 1;
      renderHistoryReport(record);
    }
  }
  if (button.dataset.historyAction === 'show-original') {
    const record = loadHistory().find(r => String(r.id) === String(id));
    if (record) showOriginalHistoryReport(record);
  }
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
  const conf = normalizedConfidenceLevel(result.confidenceLevel);

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
      <h4>${t('confidence_level_label')} — ${escapeHtml(normalizedConfidenceLevel(result.confidenceLevel))}</h4>
      <p>${escapeHtml(result.confidenceExplanation || t('no_explanation'))}</p>
    </div>
  `;
}

// Helper to clean leading numbering prefixes from action/recommendation items
// Handles: "1. ", "**1.** ", "1) ", "**1)** ", "1 - " (space-dash), etc.
// Does NOT strip numbers that appear mid-sentence (e.g. "Use 2FA" or "Within 24 hours").
function cleanActionNumbering(item) {
  if (!item) return '';
  return String(item)
    // Covers: "1. ", "**1.** ", "1) ", "**1)** " (optionally followed by dash/em-dash)
    .replace(/^\s*(?:\*\*)?\d+[\.\)](?:\*\*)?\s*[-–—]?\s*/, '')
    // Covers: "1 - ", "2 — " (digit + space + dash, NOT preceded by other text)
    .replace(/^\s*\d+\s+[-–—]\s+/, '')
    .trim();
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
      const clean = cleanActionNumbering(item);
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
  const info = r.emailInfo || {};
  const evidence = r.evidenceAnalysis || {};

  // Email info table rows matching Section 2
  const emailInfoRows = [
    [t('info_sender_name'),   info.senderName    || meta?.senderName  || '—'],
    [t('info_sender_email'),  info.senderEmail   || meta?.senderEmail || '—'],
    [t('info_sender_domain'), info.senderDomain  || '—'],
    [t('info_subject'),       info.subject       || meta?.subject     || '—'],
    [t('info_urls'),          info.urlsProvided  || t('info_none')],
    [t('info_headers'),       info.headersProvided || t('info_not_provided')],
    ['SPF',                   info.spf           || t('info_not_provided')],
    ['DKIM',                  info.dkim          || t('info_not_provided')],
    ['DMARC',                 info.dmarc         || t('info_not_provided')],
  ];

  // Evidence sections matching Section 8
  const evidenceSections = [
    { label: t('evidence_confirmed'),  cssClass: 'evidence-confirmed',  items: evidence.confirmedObservations || [] },
    { label: t('evidence_suspicious'), cssClass: 'evidence-suspicious', items: evidence.suspiciousIndicators  || [] },
    { label: t('evidence_unverified'), cssClass: 'evidence-unverified', items: evidence.unverifiedAssumptions  || [] },
  ];

  return `
    <!-- Top Risk & Confidence Banner -->
    <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:20px;padding:14px 18px;background:var(--bg-elevated);border-radius:var(--radius-lg);border:1px solid var(--border);">
      <div style="display:flex;align-items:center;gap:8px;">
        <span style="font-size:0.75rem;text-transform:uppercase;letter-spacing:0.05em;color:var(--text-muted);font-weight:700;">${t('risk_label')}:</span>
        ${riskBadgeHtml(r.riskLevel)}
      </div>
      <div style="display:flex;align-items:center;gap:8px;">
        <span style="font-size:0.75rem;text-transform:uppercase;letter-spacing:0.05em;color:var(--text-muted);font-weight:700;">${t('confidence_label')}:</span>
        ${confidenceValueBadgeHtml(r.confidenceLevel)}
      </div>
      <div style="margin-left:auto;display:flex;align-items:center;gap:8px;">
        <span class="badge ${classificationBadgeClass(r.threatClassification)}">${escapeHtml(r.threatClassification || '—')}</span>
      </div>
    </div>

    <!-- 1. Executive Summary -->
    <div class="card" style="margin-bottom:16px;">
      <div class="card-header">
        <h3 class="card-title">${t('result_sec1')}</h3>
      </div>
      <div class="card-body">
        <p style="font-size:0.875rem;color:var(--text-secondary);line-height:1.6;margin:0;">${escapeHtml(r.executiveSummary || '')}</p>
      </div>
    </div>

    <!-- 2. Email Information -->
    <div class="card" style="margin-bottom:16px;">
      <div class="card-header">
        <h3 class="card-title">${t('result_sec2')}</h3>
      </div>
      <div class="card-body" style="padding:0;overflow-x:auto;">
        <table class="data-table" style="margin:0;">
          <tbody>
            ${emailInfoRows.map(([label, value]) => `
              <tr>
                <td style="width:200px;font-weight:600;color:var(--text-muted);font-size:0.85rem;">${escapeHtml(label)}</td>
                <td style="font-size:0.875rem;">${escapeHtml(value)}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    </div>

    <!-- 3. Sender Identity Analysis -->
    <div class="card" style="margin-bottom:16px;">
      <div class="card-header">
        <h3 class="card-title">${t('result_sec3')}</h3>
      </div>
      <div class="card-body">
        <p style="font-size:0.875rem;color:var(--text-secondary);line-height:1.6;white-space:pre-wrap;margin:0;">${escapeHtml(r.senderAnalysis || t('info_not_provided'))}</p>
      </div>
    </div>

    <!-- 4. Social Engineering Detection -->
    <div class="card" style="margin-bottom:16px;">
      <div class="card-header">
        <h3 class="card-title">${t('result_sec4')}</h3>
      </div>
      <div class="card-body">
        <p style="font-size:0.875rem;color:var(--text-secondary);line-height:1.6;white-space:pre-wrap;margin:0;">${escapeHtml(r.socialEngineeringAnalysis || t('info_not_provided'))}</p>
      </div>
    </div>

    <!-- 5. URL and Domain Analysis -->
    <div class="card" style="margin-bottom:16px;">
      <div class="card-header">
        <h3 class="card-title">${t('result_sec5')}</h3>
      </div>
      <div class="card-body">
        <p style="font-size:0.875rem;color:var(--text-secondary);line-height:1.6;white-space:pre-wrap;margin:0;">${escapeHtml(r.urlAnalysis || t('info_not_provided'))}</p>
      </div>
    </div>

    <!-- 6. Email Header & Authentication Analysis -->
    <div class="card" style="margin-bottom:16px;">
      <div class="card-header">
        <h3 class="card-title">${t('result_sec6')}</h3>
      </div>
      <div class="card-body">
        <p style="font-size:0.875rem;color:var(--text-secondary);line-height:1.6;white-space:pre-wrap;margin:0;">${escapeHtml(r.headerAnalysis || t('info_not_provided'))}</p>
      </div>
    </div>

    <!-- 7. Suspicious Indicators -->
    <div class="card" style="margin-bottom:16px;">
      <div class="card-header">
        <h3 class="card-title">${t('result_sec7')}</h3>
      </div>
      <div class="card-body">
        ${(!r.suspiciousIndicators || r.suspiciousIndicators.length === 0) ? `
          <p style="color:var(--text-muted);font-size:0.875rem;margin:0;">${t('no_indicators_msg')}</p>
        ` : `
          <div class="indicators-container">
            ${r.suspiciousIndicators.map(ind => `
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
            `).join('')}
          </div>
        `}
      </div>
    </div>

    <!-- 8. Evidence Analysis -->
    <div class="card" style="margin-bottom:16px;">
      <div class="card-header">
        <h3 class="card-title">${t('result_sec8')}</h3>
      </div>
      <div class="card-body">
        <div class="evidence-grid">
          ${evidenceSections.map(s => `
            <div class="evidence-section">
              <div class="evidence-section-title ${escapeHtml(s.cssClass)}">${s.label}</div>
              <ul class="evidence-list">
                ${s.items.length
                  ? s.items.map(item => `<li>${escapeHtml(item)}</li>`).join('')
                  : `<li style="color:var(--text-muted)">${t('evidence_no_items')}</li>`
                }
              </ul>
            </div>
          `).join('')}
        </div>
      </div>
    </div>

    <!-- 9–10. Threat Classification & Risk Assessment -->
    <div class="card" style="margin-bottom:16px;">
      <div class="card-header">
        <h3 class="card-title">${t('result_sec910')}</h3>
      </div>
      <div class="card-body">
        <div class="classification-block" style="margin-bottom:16px;">
          <div>
            <div class="classification-label">${t('classification_label')}</div>
            <div class="classification-value" style="margin-top:4px;">
              <span class="badge ${classificationBadgeClass(r.threatClassification)}">${escapeHtml(r.threatClassification || '—')}</span>
            </div>
          </div>
          <div style="margin-left:auto;display:flex;gap:10px;align-items:center;flex-wrap:wrap;">
            <div>${riskBadgeHtml(r.riskLevel)}</div>
            <div>${confidenceBadgeHtml(r.confidenceLevel)}</div>
          </div>
        </div>

        <div class="risk-explanation">
          <div class="risk-explanation-block">
            <h4>${t('risk_level_label')} — ${escapeHtml(r.riskLevel || '—')}</h4>
            <p>${escapeHtml(r.riskExplanation || t('no_explanation'))}</p>
          </div>
          <div class="risk-explanation-block" style="margin-top:14px;">
            <h4>${t('confidence_level_label')} — ${escapeHtml(normalizedConfidenceLevel(r.confidenceLevel))}</h4>
            <p>${escapeHtml(r.confidenceExplanation || t('no_explanation'))}</p>
          </div>
        </div>
      </div>
    </div>

    <!-- 11. Recommended Actions -->
    <div class="card" style="margin-bottom:16px;">
      <div class="card-header">
        <h3 class="card-title">${t('result_sec11')}</h3>
      </div>
      <div class="card-body">
        ${(!r.recommendedActions || r.recommendedActions.length === 0) ? `
          <p style="color:var(--text-muted);font-size:0.875rem;margin:0;">${t('no_items_provided')}</p>
        ` : `
          <ol class="action-list">
            ${r.recommendedActions.map((item, i) => {
              const clean = cleanActionNumbering(item);
              return `<li><span class="action-number">${i + 1}.</span> ${escapeHtml(clean)}</li>`;
            }).join('')}
          </ol>
        `}
      </div>
    </div>

    <!-- 12. Investigation Limitations -->
    <div class="card" style="margin-bottom:16px;">
      <div class="card-header">
        <h3 class="card-title">${t('result_sec12')}</h3>
      </div>
      <div class="card-body">
        ${(!r.investigationLimitations || r.investigationLimitations.length === 0) ? `
          <p style="color:var(--text-muted);font-size:0.875rem;margin:0;">${t('no_items_provided')}</p>
        ` : `
          <ul class="limitation-list">
            ${r.investigationLimitations.map(item => `<li>${escapeHtml(item)}</li>`).join('')}
          </ul>
        `}
      </div>
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

function normalizedConfidenceLevel(level) {
  const raw = String(level || '').toUpperCase();
  const match = raw.match(/\b(LOW|MEDIUM|HIGH)\b/);
  return match ? match[1] : 'UNKNOWN';
}

function confidenceValueBadgeHtml(level) {
  const l = normalizedConfidenceLevel(level);
  const cls = { HIGH: 'badge-conf-high', MEDIUM: 'badge-conf-medium', LOW: 'badge-conf-low' }[l] || 'badge-conf-low';
  return `<span class="badge ${cls}">${escapeHtml(l)}</span>`;
}

function confidenceBadgeHtml(level) {
  const l = normalizedConfidenceLevel(level);
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

  // ---- Theme ----
  applyTheme(document.documentElement.getAttribute('data-theme') || 'dark');
  $('themeToggle')?.addEventListener('click', toggleTheme);

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
      // Keep an open History report visible while translating it to the new language.
      refreshOpenHistoryReport();
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
    closeHistoryModal();
  });

  $('historyModal')?.addEventListener('click', (e) => {
    if (e.target === $('historyModal')) {
      closeHistoryModal();
    }
  });

  // Both Dashboard and History use the same localStorage-backed report action.
  $('recentActivityBody')?.addEventListener('click', handleHistoryAction);
  $('historyTableBody')?.addEventListener('click', handleHistoryAction);
  $('modalBody')?.addEventListener('click', handleHistoryAction);

  // ---- Keyboard: close modal on Escape ----
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      const modal = $('historyModal');
      if (modal && modal.style.display !== 'none') {
        closeHistoryModal();
      }
      closeMobileSidebar();
    }
  });

  // ---- Initial load ----
  // Apply saved language first (sets all data-i18n text before navigation renders content)
  applyTranslations();
  applyTheme(document.documentElement.getAttribute('data-theme') || 'dark');
  checkApiHealth();
  navigateTo('dashboard');
  updateCharCount();
});
