/* ==========================================================
   АИС «Комнатки» — работающий макет (прототип)
   Практическое занятие № 5. Все данные вымышленные.
   Хранилище: localStorage браузера (имитация БД учебного стенда).
   ========================================================== */
(function () {
  'use strict';

  /* ---------------- Утилиты ---------------- */
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  // Экранирование вывода — защита от XSS при отображении введённых данных
  const esc = (v) => String(v == null ? '' : v)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');

  const pad = (n) => String(n).padStart(2, '0');
  const isoDate = (d) => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
  const TODAY = isoDate(new Date());
  const addDays = (iso, n) => { const d = parseISO(iso); d.setDate(d.getDate() + n); return isoDate(d); };
  const parseISO = (iso) => { const [y, m, d] = iso.split('-').map(Number); return new Date(y, m - 1, d); };
  const daysBetween = (a, b) => Math.round((parseISO(b) - parseISO(a)) / 86400000);
  const fmtDate = (iso) => iso ? iso.split('-').reverse().join('.') : '—';
  const fmtDT = (ts) => { const d = new Date(ts); return `${pad(d.getDate())}.${pad(d.getMonth() + 1)}.${d.getFullYear()} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`; };
  const money = (n) => new Intl.NumberFormat('ru-RU').format(Math.round(n || 0)) + ' ₽';
  const plural = (n, f) => { const a = Math.abs(n) % 100, b = a % 10; return f[(a > 10 && a < 20) ? 2 : b === 1 ? 0 : (b >= 2 && b <= 4) ? 1 : 2]; };
  const isValidISO = (s) => /^\d{4}-\d{2}-\d{2}$/.test(s) && isoDate(parseISO(s)) === s;

  const store = {
    get(key, fallback) { try { const v = localStorage.getItem(key); return v ? JSON.parse(v) : fallback; } catch (e) { return fallback; } },
    set(key, val) { try { localStorage.setItem(key, JSON.stringify(val)); } catch (e) { /* хранилище недоступно */ } },
    del(key) { try { localStorage.removeItem(key); } catch (e) { } },
    sget(key) { try { const v = sessionStorage.getItem(key); return v ? JSON.parse(v) : null; } catch (e) { return null; } },
    sset(key, val) { try { sessionStorage.setItem(key, JSON.stringify(val)); } catch (e) { } },
    sdel(key) { try { sessionStorage.removeItem(key); } catch (e) { } },
  };

  /* ---------------- SHA-256 (хэширование паролей и цепочки журнала) ---------------- */
  function sha256ascii(ascii) {
    const rr = (v, a) => (v >>> a) | (v << (32 - a));
    const maxWord = Math.pow(2, 32);
    let result = '';
    const words = [];
    const bitLen = ascii.length * 8;
    let hash = [], k = [];
    let primeCounter = 0;
    const isComposite = {};
    for (let c = 2; primeCounter < 64; c++) {
      if (!isComposite[c]) {
        for (let i = 0; i < 313; i += c) isComposite[i] = c;
        hash[primeCounter] = (Math.pow(c, .5) * maxWord) | 0;
        k[primeCounter++] = (Math.pow(c, 1 / 3) * maxWord) | 0;
      }
    }
    hash = hash.slice(0, 8);
    ascii += '\x80';
    while (ascii.length % 64 - 56) ascii += '\x00';
    for (let i = 0; i < ascii.length; i++) {
      const j = ascii.charCodeAt(i);
      words[i >> 2] |= j << ((3 - i) % 4) * 8;
    }
    words[words.length] = ((bitLen / maxWord) | 0);
    words[words.length] = bitLen;
    for (let j = 0; j < words.length;) {
      const w = words.slice(j, j += 16);
      const oldHash = hash;
      hash = hash.slice(0, 8);
      for (let i = 0; i < 64; i++) {
        const w15 = w[i - 15], w2 = w[i - 2];
        const a = hash[0], e = hash[4];
        const t1 = hash[7] + (rr(e, 6) ^ rr(e, 11) ^ rr(e, 25)) + ((e & hash[5]) ^ ((~e) & hash[6])) + k[i]
          + (w[i] = (i < 16) ? w[i] : (w[i - 16] + (rr(w15, 7) ^ rr(w15, 18) ^ (w15 >>> 3)) + w[i - 7] + (rr(w2, 17) ^ rr(w2, 19) ^ (w2 >>> 10))) | 0);
        const t2 = (rr(a, 2) ^ rr(a, 13) ^ rr(a, 22)) + ((a & hash[1]) ^ (a & hash[2]) ^ (hash[1] & hash[2]));
        hash = [(t1 + t2) | 0].concat(hash);
        hash[4] = (hash[4] + t1) | 0;
      }
      for (let i = 0; i < 8; i++) hash[i] = (hash[i] + oldHash[i]) | 0;
    }
    for (let i = 0; i < 8; i++) for (let j = 3; j + 1; j--) { const b = (hash[i] >> (j * 8)) & 255; result += ((b < 16) ? 0 : '') + b.toString(16); }
    return result;
  }
  const sha256 = (s) => sha256ascii(unescape(encodeURIComponent(String(s))));
  const randomSalt = () => { const a = new Uint8Array(8); (window.crypto || window.msCrypto).getRandomValues(a); return Array.from(a, (b) => b.toString(16).padStart(2, '0')).join(''); };

  /* ---------------- Иконки ---------------- */
  const P = {
    home: '<path d="M3 10.5 12 3l9 7.5V20a1 1 0 0 1-1 1h-5v-6H9v6H4a1 1 0 0 1-1-1z"/>',
    bed: '<path d="M2 18V6M2 14h20v4M22 18v-6a3 3 0 0 0-3-3h-8v5"/><circle cx="6.5" cy="10.5" r="2"/>',
    calendar: '<rect x="3" y="4.5" width="18" height="16.5" rx="2"/><path d="M3 9.5h18M8 2.5v4M16 2.5v4"/>',
    users: '<circle cx="9" cy="8" r="3.5"/><path d="M2.5 20a6.5 6.5 0 0 1 13 0M16 4.6a3.5 3.5 0 0 1 0 6.8M18.5 14.2A6.5 6.5 0 0 1 21.5 20"/>',
    wallet: '<path d="M3 7a2 2 0 0 1 2-2h13v4"/><rect x="3" y="7" width="18" height="13" rx="2"/><circle cx="16.5" cy="13.5" r="1.2"/>',
    chat: '<path d="M21 12a8 8 0 0 1-11.6 7.1L4 20.5l1.4-4.6A8 8 0 1 1 21 12z"/>',
    doc: '<path d="M14 3H6a1 1 0 0 0-1 1v16a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1V8z"/><path d="M14 3v5h5M8.5 13h7M8.5 17h5"/>',
    shield: '<path d="M12 3 4.5 6v5.5c0 4.6 3.2 8.3 7.5 9.5 4.3-1.2 7.5-4.9 7.5-9.5V6z"/><path d="m9 12 2 2 4-4"/>',
    key: '<circle cx="8" cy="15" r="4"/><path d="m10.8 12.2 9.2-9.2M17 6l3 3M14.5 8.5l2 2"/>',
    sliders: '<path d="M4 6h10M18 6h2M4 12h4M12 12h8M4 18h12M20 18h0"/><circle cx="16" cy="6" r="2"/><circle cx="10" cy="12" r="2"/><circle cx="18" cy="18" r="2"/>',
    info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v6M12 7.5v.01"/>',
    logout: '<path d="M15 4h4a1 1 0 0 1 1 1v14a1 1 0 0 1-1 1h-4M10 17l5-5-5-5M15 12H3"/>',
    lock: '<rect x="4" y="10.5" width="16" height="10.5" rx="2"/><path d="M8 10.5V7a4 4 0 0 1 8 0v3.5"/>',
    unlock: '<rect x="4" y="10.5" width="16" height="10.5" rx="2"/><path d="M8 10.5V7a4 4 0 0 1 7.7-1.5"/>',
    eye: '<path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
    eyeoff: '<path d="M3 3l18 18M10.6 5.1A10 10 0 0 1 12 5c6.4 0 10 7 10 7a17 17 0 0 1-3.2 4M6.6 6.6C3.8 8.4 2 12 2 12s3.6 7 10 7c1.6 0 3-.4 4.3-1M9.9 9.9a3 3 0 0 0 4.2 4.2"/>',
    search: '<circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/>',
    plus: '<path d="M12 5v14M5 12h14"/>',
    edit: '<path d="M4 20h4L19 9l-4-4L4 16z"/><path d="m13.5 6.5 4 4"/>',
    trash: '<path d="M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13M10 11v6M14 11v6"/>',
    print: '<path d="M7 9V3h10v6"/><rect x="3" y="9" width="18" height="8" rx="2"/><path d="M7 14h10v7H7z"/>',
    download: '<path d="M12 3v12M7 10l5 5 5-5M4 21h16"/>',
    alert: '<path d="M12 3 2 20h20z"/><path d="M12 10v4M12 17v.01"/>',
    check: '<path d="m5 12.5 4.5 4.5L19 7.5"/>',
    x: '<path d="M6 6l12 12M18 6 6 18"/>',
    clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
    back: '<path d="M15 5 8 12l7 7"/>',
    menu: '<path d="M4 6h16M4 12h16M4 18h16"/>',
    money: '<rect x="2.5" y="6" width="19" height="12" rx="2"/><circle cx="12" cy="12" r="2.5"/><path d="M6 9.5v5M18 9.5v5"/>',
    star: '<path d="m12 3 2.8 5.7 6.2.9-4.5 4.4 1.1 6.2L12 17.3 6.4 20.2l1.1-6.2L3 9.6l6.2-.9z"/>',
    building: '<path d="M4 21V5a1 1 0 0 1 1-1h9a1 1 0 0 1 1 1v16M15 9h4a1 1 0 0 1 1 1v11M2 21h20M8 8h3M8 12h3M8 16h3"/>',
    hotel: '<path d="M5 21V10l7-5 7 5v11h-5v-6h-4v6z"/>',
    fingerprint: '<path d="M12 11v3a8 8 0 0 1-1.5 4.7M8.5 7.6A5 5 0 0 1 17 11v1.5M7 11a5 5 0 0 1 .2-1.5M7 14.5a12 12 0 0 1-1 4M17 16a17 17 0 0 1-.8 3.5M12 7a4 4 0 0 0-4 4v1a10 10 0 0 1-1.2 4.8M14 11v2a13 13 0 0 1-1.4 6"/>',
    timer: '<circle cx="12" cy="13" r="8"/><path d="M12 9v4l2.5 1.5M9.5 2.5h5"/>',
    masks: '<path d="M3 5h18v6a9 9 0 0 1-18 0z"/><path d="M8 10h.01M16 10h.01M9 14.5c1.7 1.3 4.3 1.3 6 0"/>',
    list: '<path d="M8 6h13M8 12h13M8 18h13M3.5 6h.01M3.5 12h.01M3.5 18h.01"/>',
    refresh: '<path d="M20 11a8 8 0 0 0-14.6-4.5L4 8M4 4v4h4M4 13a8 8 0 0 0 14.6 4.5L20 16M20 20v-4h-4"/>',
    filter: '<path d="M3 5h18l-7 8.5V20l-4-2v-4.5z"/>',
  };
  const icon = (name, cls = '') => `<svg class="${cls}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${P[name] || ''}</svg>`;

  /* ---------------- Роли, разделы, права ---------------- */
  const ROLES = {
    reception: { name: 'Администратор рецепции', short: 'Рецепция' },
    cashier: { name: 'Кассир', short: 'Касса' },
    marketer: { name: 'Маркетолог', short: 'Маркетинг' },
    director: { name: 'Руководство', short: 'Руководство' },
    secadmin: { name: 'Администратор безопасности', short: 'Безопасность' },
  };
  const ALL = Object.keys(ROLES);

  const NAV = [
    { id: 'dashboard', title: 'Главная', icon: 'home', group: 'Общее', roles: ALL },
    { id: 'rooms', title: 'Номерной фонд', icon: 'bed', group: 'Операции', roles: ['reception', 'director'] },
    { id: 'bookings', title: 'Бронирования', icon: 'calendar', group: 'Операции', roles: ['reception', 'cashier', 'director'] },
    { id: 'guests', title: 'Гости', icon: 'users', group: 'Операции', roles: ['reception', 'cashier'] },
    { id: 'accounts', title: 'Лицевые счета', icon: 'wallet', group: 'Финансы и маркетинг', roles: ['cashier', 'director'] },
    { id: 'reviews', title: 'Отзывы и жалобы', icon: 'chat', group: 'Финансы и маркетинг', roles: ['marketer', 'director'] },
    { id: 'reports', title: 'Отчёты', icon: 'doc', group: 'Финансы и маркетинг', roles: ['reception', 'cashier', 'marketer', 'director'] },
    { id: 'audit', title: 'Журнал событий', icon: 'shield', group: 'Безопасность', roles: ['secadmin'] },
    { id: 'users', title: 'Учётные записи', icon: 'key', group: 'Безопасность', roles: ['secadmin'] },
    { id: 'policy', title: 'Политика безопасности', icon: 'sliders', group: 'Безопасность', roles: ['secadmin'] },
    { id: 'about', title: 'О прототипе', icon: 'info', group: 'Справка', roles: ALL },
  ];
  // Вложенные экраны наследуют права раздела
  const SUBROUTES = { guest: 'guests', booking: 'bookings' };

  const CAN = {
    editBooking: ['reception'],
    editGuest: ['reception'],
    revealPD: ['reception'],
    addCharge: ['cashier'],
    takePayment: ['cashier'],
    editReview: ['marketer'],
  };
  const can = (action) => !!App.user && CAN[action].includes(App.user.role);

  const REPORTS = [
    { id: 'bookings', title: 'Бронирования за период', pd: true, roles: ['reception', 'cashier', 'director'] },
    { id: 'occupancy', title: 'Загрузка номерного фонда', pd: false, roles: ['reception', 'marketer', 'director'] },
    { id: 'debts', title: 'Задолженности постояльцев', pd: true, roles: ['cashier', 'director'] },
    { id: 'popularity', title: 'Популярность категорий и услуг', pd: false, roles: ['marketer', 'director'] },
  ];

  const SERVICES = [
    { id: 's1', cat: 'Бытовые услуги', name: 'Прачечная (комплект)', price: 600 },
    { id: 's2', cat: 'Бытовые услуги', name: 'Химчистка (изделие)', price: 1200 },
    { id: 's3', cat: 'Бытовые услуги', name: 'Дополнительная уборка номера', price: 900 },
    { id: 's4', cat: 'Питание', name: 'Ресторан (ужин)', price: 2500 },
    { id: 's5', cat: 'Питание', name: 'Бар', price: 800 },
    { id: 's6', cat: 'Питание', name: 'Дополнительное питание в номер', price: 1500 },
    { id: 's7', cat: 'Досуг', name: 'Бассейн (посещение)', price: 700 },
    { id: 's8', cat: 'Досуг', name: 'Сауна (2 часа)', price: 1800 },
    { id: 's9', cat: 'Досуг', name: 'Бильярд (час)', price: 1000 },
  ];
  const CATEGORIES = { 'Стандарт': 1, 'Комфорт': 1.4, 'Люкс': 2.2 };
  const CAPACITY_K = { 1: 0.8, 2: 1, 3: 1.25 };
  const BOOKING_STATUSES = ['Забронировано', 'Заселён', 'Выселен', 'Отменено'];
  const PAY_METHODS = ['Наличные', 'Банковская карта', 'Безналичный расчёт (юрлицо)'];
  const PD_REASONS = ['Заселение / проверка документа', 'Оформление договора проживания', 'Ответ на запрос гостя', 'Исправление ошибки в данных'];

  const DEFAULT_POLICY = { maxAttempts: 5, lockMin: 15, timeoutMin: 5, revealSec: 30, watermark: true };

  // Демонстрационные учётные записи учебного стенда
  const DEMO_USERS = [
    { login: 'reception', password: 'Recept!2026', name: 'Иванова Анна Сергеевна', role: 'reception' },
    { login: 'cashier', password: 'Kassa!2026', name: 'Петров Максим Олегович', role: 'cashier' },
    { login: 'marketing', password: 'Market!2026', name: 'Орлова Дарья Игоревна', role: 'marketer' },
    { login: 'director', password: 'Direct!2026', name: 'Громов Виктор Павлович', role: 'director' },
    { login: 'security', password: 'Secur!2026', name: 'Соболев Денис Андреевич', role: 'secadmin' },
  ];

  /* ---------------- Тестовые данные (вымышленные) ---------------- */
  function seedDB() {
    const buildings = [
      { id: 'b1', name: 'Северный', stars: 5, floors: 9, roomsPerFloor: 12, base: 9000 },
      { id: 'b2', name: 'Парковый', stars: 4, floors: 6, roomsPerFloor: 10, base: 6000 },
      { id: 'b3', name: 'Морской', stars: 3, floors: 5, roomsPerFloor: 8, base: 4000 },
    ];
    const roomDefs = {
      b1: [[301, 'Стандарт', 2], [302, 'Стандарт', 1], [305, 'Комфорт', 2], [510, 'Комфорт', 3], [512, 'Люкс', 2], [701, 'Люкс', 2], [702, 'Комфорт', 2], [901, 'Люкс', 3]],
      b2: [[101, 'Стандарт', 1], [102, 'Стандарт', 2], [203, 'Стандарт', 3], [204, 'Комфорт', 2], [305, 'Комфорт', 2], [401, 'Люкс', 2], [402, 'Комфорт', 2], [601, 'Люкс', 3]],
      b3: [[101, 'Стандарт', 2], [102, 'Стандарт', 2], [103, 'Стандарт', 3], [201, 'Стандарт', 1], [202, 'Комфорт', 2], [301, 'Комфорт', 2], [402, 'Комфорт', 3], [501, 'Люкс', 2]],
    };
    const rooms = [];
    buildings.forEach((b) => roomDefs[b.id].forEach(([num, cat, cap]) => rooms.push({
      id: `${b.id}-${num}`, buildingId: b.id, number: String(num), floor: Math.floor(num / 100), category: cat, capacity: cap,
    })));
    const guests = [
      ['Смирнов', 'Алексей', 'Викторович', '1985-03-14', '4510 238471', '+7 (916) 245-18-67', 'a.smirnov@mail.ru'],
      ['Кузнецова', 'Марина', 'Олеговна', '1990-07-22', '4612 594013', '+7 (903) 117-42-90', 'marina.k@yandex.ru'],
      ['Попов', 'Дмитрий', 'Сергеевич', '1978-11-05', '4005 773120', '+7 (925) 668-03-11', 'popov.ds@turmarket.ru'],
      ['Васильева', 'Екатерина', 'Андреевна', '1995-01-30', '4518 120944', '+7 (977) 301-55-28', 'e.vasileva@turmarket.ru'],
      ['Соколов', 'Игорь', 'Павлович', '1982-09-17', '4709 845632', '+7 (915) 902-37-44', 'sokolov@turmarket.ru'],
      ['Михайлова', 'Ольга', 'Николаевна', '1988-04-08', '4614 309871', '+7 (926) 455-76-12', 'olga.m@gmail.com'],
      ['Новиков', 'Артём', 'Игоревич', '2000-12-02', '4520 671205', '+7 (999) 813-20-65', 'novikov.a@mail.ru'],
      ['Фёдорова', 'Анна', 'Михайловна', '1975-06-25', '4002 458819', '+7 (905) 274-91-03', 'fedorova@dialog-congress.ru'],
      ['Морозов', 'Сергей', 'Александрович', '1969-02-11', '4501 993457', '+7 (917) 640-28-39', 'morozov@dialog-congress.ru'],
      ['Волкова', 'Татьяна', 'Юрьевна', '1992-08-19', '4615 207736', '+7 (968) 732-11-50', 't.volkova@yandex.ru'],
      ['Алексеев', 'Павел', 'Денисович', '1986-10-03', '4011 562094', '+7 (921) 380-64-77', ''],
      ['Лебедева', 'Юлия', 'Романовна', '1998-05-27', '4519 834410', '+7 (985) 119-07-26', 'lebedeva.yr@mail.ru'],
      ['Семёнов', 'Константин', 'Ильич', '1980-01-15', '4706 418253', '+7 (910) 526-83-90', 'k.semenov@bk.ru'],
      ['Егорова', 'Наталья', 'Викторовна', '1993-03-09', '4617 690128', '+7 (964) 248-35-17', 'egorova@expoforum-yug.ru'],
    ].map((g, i) => ({
      id: 'g' + (i + 1), lastName: g[0], firstName: g[1], middleName: g[2], birth: g[3], passport: g[4], phone: g[5], email: g[6],
      consent: addDays(TODAY, -60 + i), created: addDays(TODAY, -60 + i),
    }));
    const companies = [
      { id: 'c1', name: 'ООО «ТурМаркет»', kind: 'Туристическая фирма', discount: 10, contract: 'КД-2026/014', until: addDays(TODAY, 150) },
      { id: 'c2', name: 'АНО «Конгресс-центр „Диалог“»', kind: 'Организатор конгрессов и симпозиумов', discount: 15, contract: 'КД-2026/021', until: addDays(TODAY, 240) },
      { id: 'c3', name: 'ООО «ЭкспоФорум-Юг»', kind: 'Организатор выставок и семинаров', discount: 12, contract: 'КД-2026/033', until: addDays(TODAY, 90) },
      { id: 'c4', name: 'ООО «Карнавал-Тур»', kind: 'Новый партнёр (маркетинговая кампания)', discount: 8, contract: 'КД-2026/040', until: addDays(TODAY, 365) },
    ];
    const B = [
      ['g1', 'b1-512', null, -3, 2, 'Заселён', 1, 0.5],
      ['g2', 'b2-204', null, -1, 3, 'Заселён', 2, 1],
      ['g3', 'b1-305', 'c1', -2, 4, 'Заселён', 1, 0],
      ['g4', 'b1-302', 'c1', -2, 4, 'Заселён', 1, 0],
      ['g5', 'b1-301', 'c1', -2, 4, 'Заселён', 2, 0],
      ['g6', 'b3-202', null, -10, -6, 'Выселен', 2, 1],
      ['g7', 'b3-101', null, 1, 5, 'Забронировано', 2, 0.3],
      ['g8', 'b2-401', 'c2', 3, 10, 'Забронировано', 1, 0],
      ['g9', 'b2-402', 'c2', 3, 10, 'Забронировано', 2, 0],
      ['g10', 'b3-501', null, -5, 0, 'Выселен', 2, 0.8],
      ['g11', 'b1-701', null, 7, 9, 'Забронировано', 2, 0],
      ['g12', 'b3-301', null, -1, 1, 'Заселён', 1, 0.5],
      ['g13', 'b2-102', null, 14, 18, 'Отменено', 2, 0],
      ['g14', 'b1-901', 'c3', -20, -15, 'Выселен', 3, 1],
      ['g1', 'b3-402', null, -40, -35, 'Выселен', 3, 1],
      ['g2', 'b1-702', 'c3', 20, 25, 'Забронировано', 2, 0],
      ['g6', 'b2-101', null, 0, 2, 'Забронировано', 1, 0],
    ];
    const db = { buildings, rooms, guests, companies, bookings: [], charges: [], reviews: [], seq: { booking: 0, charge: 0, review: 0, guest: guests.length, report: 0 } };
    B.forEach((b) => {
      const id = 'B-' + String(++db.seq.booking).padStart(4, '0');
      const bk = { id, guestId: b[0], roomId: b[1], companyId: b[2], checkIn: addDays(TODAY, b[3]), checkOut: addDays(TODAY, b[4]), status: b[5], persons: b[6], note: '', paid: 0, created: addDays(TODAY, Math.min(b[3], 0) - 7) };
      bk.cost = calcCost(db, bk);
      bk.paid = Math.round(bk.cost * b[7] / 100) * 100;
      db.bookings.push(bk);
    });
    const C = [
      ['B-0001', 's4', 2, -2], ['B-0001', 's8', 1, -1], ['B-0001', 's1', 1, 0],
      ['B-0002', 's5', 3, 0], ['B-0002', 's7', 2, 0],
      ['B-0003', 's4', 1, -1], ['B-0004', 's4', 1, -1], ['B-0005', 's6', 2, 0], ['B-0005', 's9', 2, -1],
      ['B-0006', 's2', 2, -8], ['B-0006', 's4', 3, -7],
      ['B-0010', 's3', 1, -3], ['B-0010', 's5', 2, -2],
      ['B-0012', 's7', 1, 0], ['B-0014', 's8', 1, -17],
    ];
    C.forEach((c) => {
      const s = SERVICES.find((x) => x.id === c[1]);
      db.charges.push({ id: 'Н-' + String(++db.seq.charge).padStart(4, '0'), bookingId: c[0], serviceId: s.id, qty: c[2], amount: s.price * c[2], date: addDays(TODAY, c[3]) });
    });
    db.bookings.filter((b) => b.status === 'Выселен').forEach((b) => { b.paid = b.cost + chargesOf(db, b.id); });
    db.bookings.find((b) => b.id === 'B-0010').paid -= 2100; // задолженность выселенного гостя

    const R = [
      ['g6', 'Отзыв', 5, 'Сервис', 'Очень вежливый персонал рецепции, быстрое заселение.', null, -6],
      ['g10', 'Жалоба', 2, 'Чистота', 'В номере не была проведена ежедневная уборка в день заезда.', 'На рассмотрении', -1],
      ['g14', 'Отзыв', 4, 'Цена', 'Корпоративная скидка порадовала, но завтрак мог бы быть разнообразнее.', null, -15],
      ['g1', 'Отзыв', 5, 'Номер', 'Люкс с прекрасным видом, обязательно вернусь.', null, -35],
      ['g2', 'Жалоба', 2, 'Шум', 'Шум из бара после 23:00 мешал отдыху.', 'Новая', 0],
      ['g12', 'Отзыв', 4, 'Питание', 'Хороший ресторан, приятные цены в баре.', null, 0],
      ['g3', 'Жалоба', 3, 'Размещение', 'Коллег из группы сначала разместили на разных этажах, потом исправили.', 'Решена', -1],
      ['g5', 'Отзыв', 3, 'Цена', 'Цены на сауну выше, чем у конкурентов.', null, -1],
    ];
    R.forEach((r) => db.reviews.push({ id: 'О-' + String(++db.seq.review).padStart(3, '0'), guestId: r[0], type: r[1], rating: r[2], topic: r[3], text: r[4], status: r[5], date: addDays(TODAY, r[6]) }));
    return db;
  }

  /* ---------------- Бизнес-логика ---------------- */
  const tariff = (db, room) => {
    const b = db.buildings.find((x) => x.id === room.buildingId);
    return Math.round(b.base * CATEGORIES[room.category] * CAPACITY_K[room.capacity] / 100) * 100;
  };
  function calcCost(db, bk) {
    const room = db.rooms.find((r) => r.id === bk.roomId);
    if (!room) return 0;
    const nights = Math.max(0, daysBetween(bk.checkIn, bk.checkOut));
    const comp = bk.companyId ? db.companies.find((c) => c.id === bk.companyId) : null;
    const disc = comp ? comp.discount : 0;
    return Math.round(nights * tariff(db, room) * (1 - disc / 100));
  }
  const chargesOf = (db, bookingId) => db.charges.filter((c) => c.bookingId === bookingId).reduce((s, c) => s + c.amount, 0);
  // Долг возникает после заселения (или при штрафной отмене); будущие брони долгом не считаются
  const debtOf = (bk) => (bk.status === 'Забронировано' ? 0 : Math.max(0, bk.cost + chargesOf(App.db, bk.id) - bk.paid));
  const isActive = (bk) => bk.status === 'Заселён' || bk.status === 'Забронировано';
  const overlaps = (a1, a2, b1, b2) => a1 < b2 && b1 < a2;
  function roomState(room, day = TODAY) {
    const bk = App.db.bookings.find((b) => b.roomId === room.id && isActive(b) && b.checkIn <= day && day < b.checkOut);
    if (!bk) return { key: 'free', label: 'Свободен', cls: 'b-ok' };
    return bk.status === 'Заселён' ? { key: 'occ', label: 'Занят', cls: 'b-ink', bk } : { key: 'res', label: 'Забронирован', cls: 'b-warn', bk };
  }
  const guestById = (id) => App.db.guests.find((g) => g.id === id);
  const roomById = (id) => App.db.rooms.find((r) => r.id === id);
  const bldById = (id) => App.db.buildings.find((b) => b.id === id);
  const compById = (id) => App.db.companies.find((c) => c.id === id);
  const fullName = (g) => g ? [g.lastName, g.firstName, g.middleName].filter(Boolean).join(' ') : '—';
  const shortName = (g) => g ? `${g.lastName} ${g.firstName[0]}.${g.middleName ? ' ' + g.middleName[0] + '.' : ''}` : '—';
  const roomLabel = (r) => r ? `${bldById(r.buildingId).name}, № ${r.number}` : '—';
  const statusBadge = (s) => `<span class="badge ${({ 'Забронировано': 'b-warn', 'Заселён': 'b-info', 'Выселен': 'b-ink', 'Отменено': 'b-bad' })[s] || ''}">${esc(s)}</span>`;

  /* ---------------- Маскирование ПДн (152-ФЗ, принцип минимизации) ---------------- */
  const mask = {
    passport: (p) => '****' + String(p).replace(/\D/g, '').slice(-4),
    phone: (p) => { const d = String(p).replace(/\D/g, ''); return d.length < 4 ? '***' : `+7 (***) ***-${d.slice(-4, -2)}-${d.slice(-2)}`; },
    email: (e) => { if (!e) return '—'; const [u, dom] = e.split('@'); return `${u[0]}${'*'.repeat(Math.max(2, u.length - 1))}@${dom}`; },
    birth: (b) => `**.**.${b.slice(0, 4)}`,
  };

  /* ---------------- Состояние приложения ---------------- */
  const KEYS = { db: 'kmn_db_v1', users: 'kmn_users_v1', locks: 'kmn_locks_v1', audit: 'kmn_audit_v1', policy: 'kmn_policy_v1', session: 'kmn_session_v1', flash: 'kmn_flash' };
  const App = { db: null, users: null, locks: null, audit: null, policy: null, user: null, session: null, route: null, ws: null };

  function initState() {
    App.policy = Object.assign({}, DEFAULT_POLICY, store.get(KEYS.policy, {}));
    App.db = store.get(KEYS.db, null);
    if (!App.db || !App.db.bookings) { App.db = seedDB(); store.set(KEYS.db, App.db); }
    App.users = store.get(KEYS.users, null);
    if (!App.users) {
      App.users = DEMO_USERS.map((u) => { const salt = randomSalt(); return { login: u.login, name: u.name, role: u.role, salt, hash: sha256(salt + ':' + u.password), disabled: false, lastLogin: null, created: Date.now() }; });
      store.set(KEYS.users, App.users);
    }
    App.locks = store.get(KEYS.locks, {});
    App.audit = store.get(KEYS.audit, []);
    // Идентификатор АРМ (имитация IP/имени рабочей станции)
    let ws = store.get('kmn_ws', null);
    if (!ws) { ws = 'АРМ-' + (10 + Math.floor(Math.random() * 80)) + ' / 10.10.1.' + (20 + Math.floor(Math.random() * 200)); store.set('kmn_ws', ws); }
    App.ws = ws;
    if (!App.audit.length) audit('SYSTEM_INIT', 'Стенд', 'Успех', 'Инициализация учебной БД (вымышленные данные)', { login: 'system', role: '—' });
  }
  const saveDB = () => store.set(KEYS.db, App.db);
  const saveUsers = () => store.set(KEYS.users, App.users);
  const saveLocks = () => store.set(KEYS.locks, App.locks);

  /* ---------------- Журнал событий (с цепочкой хэшей) ---------------- */
  const EVENTS = {
    SYSTEM_INIT: 'Инициализация системы',
    LOGIN_OK: 'Успешный вход',
    LOGIN_FAIL: 'Неудачная попытка входа',
    ACCOUNT_LOCKED: 'Блокировка учётной записи',
    LOGIN_BLOCKED: 'Вход заблокированной УЗ',
    LOGOUT: 'Выход из системы',
    SESSION_TIMEOUT: 'Завершение сеанса по тайм-ауту',
    ACCESS_DENIED: 'Попытка несанкционированного доступа',
    PD_VIEW: 'Просмотр ПДн (раскрытие)',
    GUEST_CREATE: 'Создание карточки гостя',
    GUEST_UPDATE: 'Изменение карточки гостя',
    GUEST_DELETE: 'Удаление карточки гостя',
    BOOKING_CREATE: 'Создание бронирования',
    BOOKING_UPDATE: 'Изменение бронирования',
    BOOKING_CANCEL: 'Отмена бронирования',
    BOOKING_DELETE: 'Удаление бронирования',
    CHARGE_ADD: 'Начисление услуги',
    PAYMENT: 'Приём оплаты',
    REVIEW_ADD: 'Регистрация отзыва/жалобы',
    REVIEW_STATUS: 'Изменение статуса жалобы',
    REPORT_VIEW: 'Формирование отчёта',
    REPORT_PRINT: 'Печать отчёта',
    EXPORT: 'Выгрузка данных',
    USER_UNLOCK: 'Разблокировка УЗ',
    USER_DISABLE: 'Отключение УЗ',
    USER_ENABLE: 'Включение УЗ',
    POLICY_CHANGE: 'Изменение политики безопасности',
    AUDIT_VERIFY: 'Проверка целостности журнала',
    AUDIT_EXPORT: 'Выгрузка журнала',
    DATA_RESET: 'Сброс данных стенда',
  };
  const SECURITY_EVENTS = ['LOGIN_FAIL', 'ACCOUNT_LOCKED', 'LOGIN_BLOCKED', 'ACCESS_DENIED', 'SESSION_TIMEOUT', 'USER_UNLOCK', 'USER_DISABLE', 'POLICY_CHANGE', 'PD_VIEW', 'DATA_RESET'];

  const entryHashInput = (e) => [e.n, e.ts, e.login, e.role, e.ws, e.event, e.object, e.result, e.details, e.prev].join('|');
  function audit(event, object, result, details, actor) {
    const who = actor || (App.user ? { login: App.user.login, role: ROLES[App.user.role].name } : { login: '—', role: '—' });
    const prev = App.audit.length ? App.audit[App.audit.length - 1].hash : '0'.repeat(64);
    const e = { n: App.audit.length + 1, ts: Date.now(), login: who.login, role: who.role, ws: App.ws, event, object: object || '', result: result || 'Успех', details: details || '', prev };
    e.hash = sha256(entryHashInput(e));
    App.audit.push(e);
    store.set(KEYS.audit, App.audit);
  }
  function verifyAudit() {
    let prev = '0'.repeat(64);
    for (const e of App.audit) {
      if (e.prev !== prev || sha256(entryHashInput(e)) !== e.hash) return { ok: false, n: e.n };
      prev = e.hash;
    }
    return { ok: true, n: App.audit.length };
  }

  /* ---------------- Аутентификация ---------------- */
  const lockOf = (login) => App.locks[login] || { failed: 0, lockedUntil: 0, lastFail: 0 };
  const isLocked = (login) => lockOf(login).lockedUntil > Date.now();

  function attemptLogin(loginRaw, password) {
    const login = loginRaw.trim().toLowerCase();
    if (!login || !password) return { ok: false, type: 'warn', msg: 'Введите логин и пароль.' };
    const actor = { login, role: '—' };
    if (isLocked(login)) {
      const mins = Math.ceil((lockOf(login).lockedUntil - Date.now()) / 60000);
      audit('LOGIN_BLOCKED', 'УЗ ' + login, 'Отказ', 'Попытка входа в период блокировки', actor);
      return { ok: false, type: 'lock', msg: `Учётная запись заблокирована после ${App.policy.maxAttempts} неудачных попыток входа. Повторите через ${mins} ${plural(mins, ['минуту', 'минуты', 'минут'])} или обратитесь к администратору безопасности.` };
    }
    const user = App.users.find((u) => u.login === login);
    const okPwd = user && sha256(user.salt + ':' + password) === user.hash;
    if (user && okPwd && user.disabled) {
      audit('LOGIN_FAIL', 'УЗ ' + login, 'Отказ', 'Учётная запись отключена администратором', actor);
      return { ok: false, type: 'lock', msg: 'Учётная запись отключена. Обратитесь к администратору безопасности.' };
    }
    if (!okPwd) {
      const l = lockOf(login);
      l.failed += 1; l.lastFail = Date.now();
      // Не раскрываем, существует ли логин: сообщение одинаковое для обоих случаев
      audit('LOGIN_FAIL', 'УЗ ' + login, 'Отказ', `Неверный пароль или логин (попытка ${l.failed} из ${App.policy.maxAttempts})`, actor);
      if (l.failed >= App.policy.maxAttempts) {
        l.lockedUntil = Date.now() + App.policy.lockMin * 60000;
        App.locks[login] = l; saveLocks();
        audit('ACCOUNT_LOCKED', 'УЗ ' + login, 'Предупреждение', `Блокировка на ${App.policy.lockMin} мин после ${l.failed} неудачных попыток`, actor);
        return { ok: false, type: 'lock', msg: `Превышено число попыток входа (${App.policy.maxAttempts}). Учётная запись заблокирована на ${App.policy.lockMin} минут. Событие зарегистрировано в журнале безопасности.` };
      }
      App.locks[login] = l; saveLocks();
      const left = App.policy.maxAttempts - l.failed;
      return { ok: false, type: 'bad', msg: `Неверный логин или пароль. Осталось ${left} ${plural(left, ['попытка', 'попытки', 'попыток'])} до блокировки.` };
    }
    const prevFails = lockOf(login).failed;
    const prevLogin = user.lastLogin;
    delete App.locks[login]; saveLocks();
    user.lastLogin = Date.now(); saveUsers();
    App.user = user;
    App.session = { login: user.login, started: Date.now(), last: Date.now() };
    store.sset(KEYS.session, App.session);
    audit('LOGIN_OK', 'УЗ ' + login, 'Успех', 'Аутентификация по паролю');
    return { ok: true, prevLogin, prevFails };
  }

  function logout(reason) {
    if (App.user) audit(reason === 'timeout' ? 'SESSION_TIMEOUT' : 'LOGOUT', 'УЗ ' + App.user.login, 'Успех', reason === 'timeout' ? `Бездействие более ${App.policy.timeoutMin} мин` : 'Пользователь завершил сеанс');
    App.user = null; App.session = null;
    store.sdel(KEYS.session);
    closeModal();
    if (reason === 'timeout') store.sset(KEYS.flash, { type: 'warn', msg: 'Сеанс завершён автоматически из-за бездействия. Войдите повторно.' });
    location.hash = '#login';
    render();
  }

  function restoreSession() {
    const s = store.sget(KEYS.session);
    if (!s) return;
    if (Date.now() - s.last > App.policy.timeoutMin * 60000) {
      App.user = App.users.find((u) => u.login === s.login) || null;
      if (App.user) logout('timeout');
      return;
    }
    const u = App.users.find((x) => x.login === s.login && !x.disabled);
    if (u) { App.user = u; App.session = s; }
  }

  /* ---------------- Тайм-аут бездействия ---------------- */
  let sessionTimer = null, warnOpen = false;
  function touch() {
    if (!App.session || warnOpen) return;
    App.session.last = Date.now();
    store.sset(KEYS.session, App.session);
  }
  ['mousemove', 'keydown', 'click', 'scroll', 'touchstart'].forEach((ev) => window.addEventListener(ev, throttle(touch, 1000), { passive: true }));
  function throttle(fn, ms) { let t = 0; return () => { const n = Date.now(); if (n - t > ms) { t = n; fn(); } }; }

  function startSessionTimer() {
    clearInterval(sessionTimer);
    const tick = () => {
      if (!App.session) return;
      const left = Math.ceil((App.session.last + App.policy.timeoutMin * 60000 - Date.now()) / 1000);
      const pill = $('#session-left');
      if (pill) {
        pill.textContent = `${pad(Math.floor(Math.max(left, 0) / 60))}:${pad(Math.max(left, 0) % 60)}`;
        pill.parentElement.classList.toggle('low', left <= 60);
      }
      if (left <= 0) { warnOpen = false; logout('timeout'); return; }
      if (left <= 30 && !warnOpen) {
        warnOpen = true;
        openModal(`
          <div class="modal-head"><div class="m-ico warn">${icon('timer')}</div><div><h3>Сеанс скоро завершится</h3><p>Вы не проявляли активности ${App.policy.timeoutMin} ${plural(App.policy.timeoutMin, ['минуту', 'минуты', 'минут'])}. Для защиты данных сеанс будет закрыт автоматически.</p></div></div>
          <div class="modal-body"><div class="countdown" id="countdown">${left}</div><p class="muted small" style="text-align:center;margin:0">секунд до выхода</p></div>
          <div class="modal-foot"><button class="btn" data-action="logout">Выйти сейчас</button><button class="btn btn-primary" data-action="session-continue">Продолжить работу</button></div>`, { noClose: true });
      }
      if (warnOpen) { const c = $('#countdown'); if (c) c.textContent = Math.max(left, 0); }
    };
    tick();
    sessionTimer = setInterval(tick, 1000);
  }

  /* ---------------- Модальные окна и уведомления ---------------- */
  let modalResolve = null, modalOpts = {};
  function openModal(html, opts = {}) {
    modalOpts = opts;
    $('#modal-root').innerHTML = `<div class="modal-backdrop" data-backdrop><div class="modal ${opts.wide ? 'wide' : ''}" role="dialog" aria-modal="true">${html}</div></div>`;
    const first = $('#modal-root [autofocus]') || $('#modal-root input, #modal-root select, #modal-root textarea');
    if (first) setTimeout(() => first.focus(), 30);
  }
  function closeModal(value) {
    $('#modal-root').innerHTML = '';
    if (modalOpts.onClose) modalOpts.onClose();
    modalOpts = {};
    if (modalResolve) { const r = modalResolve; modalResolve = null; r(value); }
  }
  // Подтверждение опасного действия; при requireText — ввод контрольного слова
  function confirmDanger({ title, text, confirmLabel = 'Подтвердить', danger = true, requireText = null }) {
    return new Promise((resolve) => {
      modalResolve = resolve;
      openModal(`
        <div class="modal-head"><div class="m-ico ${danger ? 'danger' : 'warn'}">${icon('alert')}</div><div><h3>${esc(title)}</h3><p>${text}</p></div></div>
        ${requireText ? `<div class="modal-body"><div class="field"><label>Для подтверждения введите слово <b>${esc(requireText)}</b></label><input class="input" id="confirm-word" autocomplete="off" autofocus></div></div>` : '<div class="modal-body"></div>'}
        <div class="modal-foot"><button class="btn" data-action="modal-cancel">Отмена</button><button class="btn ${danger ? 'btn-danger' : 'btn-primary'}" id="confirm-ok" data-action="modal-ok" ${requireText ? 'disabled' : ''}>${esc(confirmLabel)}</button></div>`);
      if (requireText) $('#confirm-word').addEventListener('input', (e) => { $('#confirm-ok').disabled = e.target.value.trim().toUpperCase() !== requireText; });
    });
  }
  function toast(msg, type = 'ok') {
    const el = document.createElement('div');
    el.className = 'toast ' + type;
    el.innerHTML = icon(type === 'ok' ? 'check' : type === 'bad' ? 'x' : 'alert') + `<div>${esc(msg)}</div>`;
    $('#toast-root').appendChild(el);
    setTimeout(() => el.remove(), 3800);
  }

  /* ---------------- Маршрутизация ---------------- */
  function parseRoute() {
    const raw = (location.hash || '').replace(/^#\/?/, '');
    const [path, query = ''] = raw.split('?');
    const parts = path.split('/').filter(Boolean);
    const params = {};
    query.split('&').filter(Boolean).forEach((kv) => { const [k, v = ''] = kv.split('='); params[decodeURIComponent(k)] = decodeURIComponent(v); });
    return { page: parts[0] || '', id: parts[1] || null, params };
  }
  const navOf = (page) => NAV.find((n) => n.id === (SUBROUTES[page] || page));
  const allowed = (page) => { const n = navOf(page); return !!n && !!App.user && n.roles.includes(App.user.role); };

  const PAGES = {};
  let lastDenied = null;
  let revealTimer = null;

  function render() {
    clearInterval(revealTimer);
    const r = parseRoute();
    App.route = r;
    if (r.page !== 'booking') Object.keys(BookingDraft).forEach((k) => delete BookingDraft[k]);
    if (!App.user) {
      clearInterval(sessionTimer);
      if (r.page === 'about') { $('#app').innerHTML = publicFrame(PAGES.about.render(r)); PAGES.about.mount && PAGES.about.mount(r); return; }
      $('#app').innerHTML = renderLogin();
      mountLogin();
      return;
    }
    if (!r.page || r.page === 'login') { location.replace('#dashboard'); return; }
    let body, title, crumbs = '', ok = false;
    const nav = navOf(r.page);
    if (!nav || !PAGES[r.page]) {
      title = 'Страница не найдена';
      body = `<div class="card denied"><div class="code">404</div><h2>Экран не найден</h2><p class="muted">Проверьте адрес или воспользуйтесь меню.</p><a class="btn btn-primary" href="#dashboard">На главную</a></div>`;
    } else if (!allowed(r.page) || (r.page === 'booking' && !can('editBooking'))) {
      title = 'Доступ запрещён';
      const screen = r.page === 'booking' ? 'Форма бронирования' : r.page === 'guest' ? 'Карточка гостя' : nav.title;
      const key = location.hash + App.user.login;
      if (lastDenied !== key) { audit('ACCESS_DENIED', 'Экран «' + screen + '»', 'Отказ', 'Переход по прямой ссылке ' + location.hash); lastDenied = key; }
      body = `<div class="card denied"><div class="code">403</div><h2>Недостаточно прав</h2><p class="muted">Экран «${esc(screen)}» недоступен для роли «${esc(ROLES[App.user.role].name)}». Попытка доступа зарегистрирована в журнале событий.</p><a class="btn btn-primary" href="#dashboard">На главную</a></div>`;
    } else {
      lastDenied = null;
      ok = true;
      const page = PAGES[r.page];
      title = typeof page.title === 'function' ? page.title(r) : page.title;
      crumbs = page.crumbs ? page.crumbs(r) : '';
      body = page.render(r);
    }
    $('#app').innerHTML = renderShell(title, crumbs, body, nav ? nav.id : '');
    const page = PAGES[r.page];
    if (ok && page.mount) page.mount(r);
    startSessionTimer();
    window.scrollTo(0, 0);
  }

  /* ---------------- Экран входа ---------------- */
  function renderLogin() {
    const flash = store.sget(KEYS.flash);
    store.sdel(KEYS.flash);
    return `
    <div class="login-wrap">
      <section class="login-hero">
        <div>
          <div class="brand"><div class="brand-mark">${icon('hotel')}</div><div><div class="brand-name">Комнатки</div><div class="brand-sub">АИС гостиничного комплекса</div></div></div>
          <h1>Единая система управления <em>гостиничным комплексом</em></h1>
          <p class="lead">Номерной фонд трёх корпусов, индивидуальное и групповое бронирование, лицевые счета гостей, отзывы и отчётность — в защищённом веб-интерфейсе.</p>
          <div class="hero-features">
            <div class="hero-feature">${icon('fingerprint')}<div>Аутентификация и блокировка после ${App.policy.maxAttempts} неудачных попыток</div></div>
            <div class="hero-feature">${icon('key')}<div>Ролевая модель доступа (RBAC): 5 ролей</div></div>
            <div class="hero-feature">${icon('masks')}<div>Маскирование персональных данных по 152-ФЗ</div></div>
            <div class="hero-feature">${icon('shield')}<div>Журнал действий с контролем целостности</div></div>
          </div>
        </div>
        <div class="hero-foot">Учебный стенд · ПЗ № 5 «Разработка прототипа АИС» · Все данные вымышленные</div>
      </section>
      <section class="login-panel">
        <div class="login-card">
          <h2>Вход в систему</h2>
          <p class="sub">Используйте учётную запись, выданную администратором безопасности.</p>
          <div id="login-alert">${flash ? alertBox(flash.type, flash.msg) : ''}</div>
          <form id="login-form" autocomplete="off" novalidate>
            <div class="field"><label for="login">Логин</label><input class="input" id="login" name="login" autocomplete="username" spellcheck="false" maxlength="32" autofocus></div>
            <div class="field"><label for="password">Пароль</label><input class="input" id="password" name="password" type="password" autocomplete="current-password" maxlength="64">
              <div class="pwd-note">${icon('eyeoff')} Пароль не отображается при вводе и не сохраняется в браузере</div></div>
            <button class="btn btn-primary btn-block" type="submit" style="height:44px">${icon('lock')} Войти</button>
          </form>
          <div class="demo-box">
            <h4>Демо-учётные записи учебного стенда</h4>
            <div class="demo-list">
              ${DEMO_USERS.map((u) => `<button type="button" class="demo-item" data-action="demo-fill" data-login="${u.login}" data-pwd="${esc(u.password)}"><span><b>${esc(ROLES[u.role].name)}</b><br><span class="mono">${u.login} / ${esc(u.password)}</span></span>${icon('back', 'rot')}</button>`).join('')}
            </div>
            <p class="small muted" style="margin:10px 0 0">Подсказка: введите неверный пароль 5 раз, чтобы увидеть блокировку учётной записи.</p>
          </div>
          <div class="login-links"><a href="#about">О прототипе и чек-лист</a><a href="#" data-action="reset-data">Сбросить демо-данные</a></div>
        </div>
      </section>
    </div>`;
  }
  const alertBox = (type, msg) => {
    const map = { bad: ['alert-bad', 'x'], lock: ['alert-bad', 'lock'], warn: ['alert-warn', 'alert'], ok: ['alert-ok', 'check'], info: ['alert-info', 'info'] };
    const [cls, ic] = map[type] || map.info;
    return `<div class="alert ${cls}">${icon(ic)}<div>${type === 'lock' ? '<b>Вход заблокирован</b>' : ''}${esc(msg)}</div></div>`;
  };
  function mountLogin() {
    $$('.demo-item svg').forEach((s) => { s.style.transform = 'rotate(180deg)'; s.style.width = '16px'; s.style.color = '#999'; });
    $('#login-form').addEventListener('submit', (e) => {
      e.preventDefault();
      const res = attemptLogin($('#login').value, $('#password').value);
      $('#password').value = '';
      if (!res.ok) {
        $('#login-alert').innerHTML = alertBox(res.type, res.msg);
        $('#password').focus();
        return;
      }
      location.hash = '#dashboard';
      render();
      const msg = res.prevLogin ? `Предыдущий вход: ${fmtDT(res.prevLogin)}` : 'Первый вход в систему';
      toast(res.prevFails ? `${msg}. Неудачных попыток с последнего входа: ${res.prevFails}` : msg, res.prevFails ? 'warn' : 'ok');
    });
  }

  /* ---------------- Каркас ---------------- */
  function renderShell(title, crumbs, body, activeId) {
    const u = App.user;
    const groups = [];
    NAV.filter((n) => n.roles.includes(u.role)).forEach((n) => {
      let g = groups.find((x) => x.name === n.group);
      if (!g) { g = { name: n.group, items: [] }; groups.push(g); }
      g.items.push(n);
    });
    const newComplaints = App.db.reviews.filter((r) => r.type === 'Жалоба' && r.status === 'Новая').length;
    const locked = App.users.filter((x) => isLocked(x.login)).length;
    const nav = groups.map((g) => `<div class="nav-group"><div class="nav-title">${esc(g.name)}</div>${g.items.map((n) => {
      let count = '';
      if (n.id === 'reviews' && newComplaints) count = `<span class="count">${newComplaints}</span>`;
      if (n.id === 'users' && locked) count = `<span class="count">${locked}</span>`;
      return `<a class="nav-link ${n.id === activeId ? 'active' : ''}" href="#${n.id}">${icon(n.icon)}<span>${esc(n.title)}</span>${count}</a>`;
    }).join('')}</div>`).join('');
    return `
    <div class="shell" id="shell">
      <aside class="sidebar">
        <div class="brand"><div class="brand-mark">${icon('hotel')}</div><div><div class="brand-name">Комнатки</div><div class="brand-sub">АИС · прототип</div></div></div>
        <div class="role-chip"><div class="who">${esc(u.name)}</div><div class="role">${icon('key')}${esc(ROLES[u.role].name)}</div></div>
        <nav>${nav}</nav>
        <div class="sidebar-foot">${esc(App.ws)}<br>Вымышленные данные · ПЗ № 5</div>
      </aside>
      <div class="main">
        ${App.policy.watermark ? watermark() : ''}
        <header class="topbar">
          <button class="btn btn-ghost btn-icon menu-toggle" data-action="toggle-nav" aria-label="Меню">${icon('menu')}</button>
          <div><div class="crumbs">${crumbs || 'АИС «Комнатки»'}</div><h1>${esc(title)}</h1></div>
          <div class="spacer"></div>
          <span class="secure-pill">${icon('lock')} TLS 1.3 · защищённое соединение</span>
          <span class="session-pill" title="Время до автоматического завершения сеанса при бездействии">${icon('timer')}<span>Сеанс</span><b id="session-left">--:--</b></span>
          <button class="btn btn-sm" data-action="logout">${icon('logout')}<span>Выход</span></button>
        </header>
        <main class="content">${body}</main>
      </div>
    </div>`;
  }
  function watermark() {
    const text = `${App.user.login} · ${fmtDT(App.session.started).slice(0, 16)} · ${App.ws.split(' / ')[0]}`;
    let s = '';
    for (let y = 0; y < 14; y++) for (let x = 0; x < 6; x++) s += `<span style="left:${x * 340 + (y % 2) * 170 - 80}px;top:${y * 110}px">${esc(text)}</span>`;
    return `<div class="watermark" aria-hidden="true">${s}</div>`;
  }
  function publicFrame(body) {
    return `<div style="max-width:1180px;margin:0 auto;padding:26px 16px 60px">
      <div style="display:flex;align-items:center;gap:14px;margin-bottom:22px;flex-wrap:wrap"><div class="brand"><div class="brand-mark">${icon('hotel')}</div><div><div class="brand-name" style="color:var(--ink)">Комнатки</div><div class="brand-sub" style="color:var(--muted)">АИС гостиничного комплекса · прототип</div></div></div><div style="flex:1"></div><a class="btn btn-primary" href="#login">${icon('lock')} Войти в систему</a></div>
      ${body}</div>`;
  }

  /* ---------------- Хелперы форм ---------------- */
  const opt = (value, label, selected) => `<option value="${esc(value)}" ${String(value) === String(selected) ? 'selected' : ''}>${esc(label)}</option>`;
  function setErr(id, msg) {
    const el = document.getElementById(id);
    if (!el) return;
    el.classList.toggle('invalid', !!msg);
    const holder = el.closest('.field').querySelector('.err');
    if (holder) holder.textContent = msg || '';
  }
  const kpi = (label, value, ic, color, delta) => `<div class="card kpi"><div class="kpi-top"><span class="label">${esc(label)}</span><span class="ico ${color || ''}">${icon(ic)}</span></div><div class="value">${value}</div>${delta ? `<div class="delta">${delta}</div>` : ''}</div>`;
  function downloadCSV(name, rows) {
    const csv = '﻿' + rows.map((r) => r.map((c) => `"${String(c == null ? '' : c).replace(/"/g, '""')}"`).join(';')).join('\r\n');
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv;charset=utf-8' }));
    a.download = name;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  }

  /* ==========================================================
     ЭКРАНЫ
     ========================================================== */

  /* ---------- Главная ---------- */
  PAGES.dashboard = {
    title: 'Главная',
    render() {
      const u = App.user, db = App.db;
      const greet = new Date().getHours() < 12 ? 'Доброе утро' : new Date().getHours() < 18 ? 'Добрый день' : 'Добрый вечер';
      const head = `<div class="welcome"><div><h2>${greet}, ${esc(u.name.split(' ')[1] || u.name)}!</h2><p>Сегодня ${fmtDate(TODAY)}. Вы вошли как «${esc(ROLES[u.role].name)}» — доступны только разделы вашей роли.</p></div></div>`;
      if (u.role === 'secadmin') return head + dashSecurity();
      const states = db.rooms.map((r) => roomState(r).key);
      const free = states.filter((s) => s === 'free').length, occ = states.filter((s) => s === 'occ').length, res = states.filter((s) => s === 'res').length;
      const arrivals = db.bookings.filter((b) => b.checkIn === TODAY && isActive(b));
      const departures = db.bookings.filter((b) => b.checkOut === TODAY && b.status === 'Заселён');
      const inHouse = db.bookings.filter((b) => b.status === 'Заселён').reduce((s, b) => s + b.persons, 0);
      const debt = db.bookings.reduce((s, b) => s + debtOf(b), 0);
      const revenue = db.bookings.filter((b) => b.status !== 'Отменено').reduce((s, b) => s + b.paid, 0);
      const avg = (db.reviews.reduce((s, r) => s + r.rating, 0) / db.reviews.length).toFixed(1);
      let cards;
      if (u.role === 'reception') cards = [kpi('Свободно номеров', free, 'bed', 'green', `из ${db.rooms.length} в 3 корпусах`), kpi('Заселено', occ, 'users', 'blue', `${inHouse} ${plural(inHouse, ['гость', 'гостя', 'гостей'])} проживает`), kpi('Заезды сегодня', arrivals.length, 'calendar', '', `выезды: ${departures.length}`), kpi('Забронировано на сегодня', res, 'clock', '', 'ожидают заселения')];
      else if (u.role === 'cashier') cards = [kpi('Задолженность гостей', money(debt), 'money', 'red', 'проживание + услуги'), kpi('Получено оплат', money(revenue), 'wallet', 'green', 'по всем бронированиям'), kpi('Начислений услуг', db.charges.length, 'list', 'blue', money(db.charges.reduce((s, c) => s + c.amount, 0))), kpi('Проживают сейчас', occ, 'users', '', 'открытые лицевые счета')];
      else if (u.role === 'marketer') cards = [kpi('Средняя оценка', avg + ' / 5', 'star', '', `${db.reviews.length} отзывов и жалоб`), kpi('Новые жалобы', db.reviews.filter((r) => r.type === 'Жалоба' && r.status === 'Новая').length, 'alert', 'red', 'требуют реакции'), kpi('Корпоративных партнёров', db.companies.length, 'building', 'blue', 'действующие договоры'), kpi('Загрузка фонда', Math.round((occ + res) / db.rooms.length * 100) + '%', 'bed', 'green', 'на сегодня')];
      else cards = [kpi('Загрузка фонда', Math.round((occ + res) / db.rooms.length * 100) + '%', 'bed', 'green', `${occ} занято, ${res} забронировано`), kpi('Выручка (оплачено)', money(revenue), 'wallet', 'blue', 'по всем бронированиям'), kpi('Дебиторская задолженность', money(debt), 'money', 'red', 'контроль кассы'), kpi('Средняя оценка гостей', avg + ' / 5', 'star', '', 'по отзывам')];

      const occBars = db.buildings.map((b) => {
        const rs = db.rooms.filter((r) => r.buildingId === b.id);
        const o = rs.filter((r) => roomState(r).key === 'occ').length, rv = rs.filter((r) => roomState(r).key === 'res').length;
        return `<div class="bar-row"><div class="name">«${esc(b.name)}» <span class="stars small">${'★'.repeat(b.stars)}</span></div><div class="bar"><i class="occ" style="width:${o / rs.length * 100}%"></i><i class="res" style="width:${rv / rs.length * 100}%"></i></div><div class="right small"><b>${Math.round((o + rv) / rs.length * 100)}%</b></div></div>`;
      }).join('');

      let side = '';
      if (u.role === 'reception' || u.role === 'director') {
        const list = arrivals.concat(db.bookings.filter((b) => b.status === 'Забронировано' && b.checkIn > TODAY).sort((a, b) => a.checkIn.localeCompare(b.checkIn))).slice(0, 5);
        side = `<div class="card"><div class="card-head"><h3>Ближайшие заезды</h3><div class="spacer"></div><a class="small" href="#bookings">Все</a></div><div class="card-body" style="padding-top:6px;padding-bottom:6px">${list.map((b) => `<div class="kv"><span>${esc(shortName(guestById(b.guestId)))}<br><span class="small muted">${esc(roomLabel(roomById(b.roomId)))}</span></span><b class="nowrap">${b.checkIn === TODAY ? 'сегодня' : fmtDate(b.checkIn)}</b></div>`).join('') || '<p class="muted">Нет заездов</p>'}</div></div>`;
      } else if (u.role === 'cashier') {
        const debtors = db.bookings.filter((b) => debtOf(b) > 0).sort((a, b) => debtOf(b) - debtOf(a)).slice(0, 5);
        side = `<div class="card"><div class="card-head"><h3>Крупнейшие задолженности</h3><div class="spacer"></div><a class="small" href="#accounts">Счета</a></div><div class="card-body" style="padding-top:6px;padding-bottom:6px">${debtors.map((b) => `<div class="kv"><span>${esc(shortName(guestById(b.guestId)))} <span class="small muted">${b.id}</span></span><b>${money(debtOf(b))}</b></div>`).join('')}</div></div>`;
      } else {
        const last = db.reviews.slice().sort((a, b) => b.date.localeCompare(a.date)).slice(0, 4);
        side = `<div class="card"><div class="card-head"><h3>Последние отзывы</h3><div class="spacer"></div><a class="small" href="#reviews">Все</a></div><div class="card-body" style="padding-top:6px;padding-bottom:6px">${last.map((r) => `<div class="kv"><span>${esc(r.topic)} · <span class="small muted">${esc(r.type)}</span><br><span class="small muted">${esc(r.text.slice(0, 52))}…</span></span><span class="rating">${'★'.repeat(r.rating)}</span></div>`).join('')}</div></div>`;
      }
      return head + `<div class="grid grid-4">${cards.join('')}</div>
        <div class="grid grid-21 section-gap">
          <div class="card"><div class="card-head"><h3>Загрузка корпусов на сегодня</h3><div class="spacer"></div><div class="legend"><span><i style="background:var(--ink)"></i>занято</span><span><i style="background:var(--gold)"></i>забронировано</span></div></div><div class="card-body">${occBars}</div></div>
          ${side}
        </div>`;
    },
  };
  function dashSecurity() {
    const day = Date.now() - 86400000;
    const recent = App.audit.filter((e) => e.ts > day);
    const fails = recent.filter((e) => e.event === 'LOGIN_FAIL').length;
    const denied = recent.filter((e) => e.event === 'ACCESS_DENIED').length;
    const pd = recent.filter((e) => e.event === 'PD_VIEW').length;
    const locked = App.users.filter((u) => isLocked(u.login)).length;
    const v = verifyAudit();
    const secRows = App.audit.filter((e) => SECURITY_EVENTS.includes(e.event)).slice(-7).reverse();
    return `<div class="grid grid-4">
      ${kpi('Неудачных входов за сутки', fails, 'fingerprint', fails ? 'red' : 'green')}
      ${kpi('Заблокировано УЗ', locked, 'lock', locked ? 'red' : 'green', `<a href="#users">управление учётными записями</a>`)}
      ${kpi('Отказов в доступе', denied, 'shield', denied ? 'red' : 'blue', 'за сутки')}
      ${kpi('Раскрытий ПДн', pd, 'eye', '', 'за сутки, с указанием цели')}
    </div>
    <div class="grid grid-21 section-gap">
      <div class="card"><div class="card-head"><h3>Последние события безопасности</h3><div class="spacer"></div><a class="small" href="#audit">Журнал</a></div>
        <div class="table-wrap"><table class="table"><thead><tr><th>Время</th><th>Пользователь</th><th>Событие</th><th>Результат</th></tr></thead><tbody>
        ${secRows.map((e) => `<tr><td class="nowrap small">${fmtDT(e.ts)}</td><td>${esc(e.login)}</td><td class="ev">${esc(EVENTS[e.event] || e.event)}</td><td>${resultBadge(e.result)}</td></tr>`).join('') || '<tr><td colspan="4" class="empty">Событий нет</td></tr>'}
        </tbody></table></div></div>
      <div class="card"><div class="card-head"><h3>Состояние защиты</h3></div><div class="card-body" style="padding-top:6px">
        <div class="kv"><span>Целостность журнала</span><b class="${v.ok ? 'chain-ok' : 'chain-bad'}">${v.ok ? '✓ не нарушена' : '✗ нарушена (№ ' + v.n + ')'}</b></div>
        <div class="kv"><span>Записей в журнале</span><b>${App.audit.length}</b></div>
        <div class="kv"><span>Порог блокировки</span><b>${App.policy.maxAttempts} попыток / ${App.policy.lockMin} мин</b></div>
        <div class="kv"><span>Тайм-аут сеанса</span><b>${App.policy.timeoutMin} мин</b></div>
        <div class="kv"><span>Водяной знак сеанса</span><b>${App.policy.watermark ? 'включён' : 'выключен'}</b></div>
        <a class="btn btn-sm section-gap" href="#policy">${icon('sliders')} Изменить политику</a>
      </div></div>
    </div>`;
  }
  const resultBadge = (r) => `<span class="badge ${r === 'Успех' ? 'b-ok' : r === 'Отказ' ? 'b-bad' : 'b-warn'}">${esc(r)}</span>`;

  /* ---------- Номерной фонд ---------- */
  PAGES.rooms = {
    title: 'Номерной фонд',
    crumbs: () => 'Операции',
    render() {
      const db = App.db;
      const bcards = db.buildings.map((b) => {
        const rs = db.rooms.filter((r) => r.buildingId === b.id);
        const free = rs.filter((r) => roomState(r).key === 'free').length;
        return `<div class="card card-pad"><div style="display:flex;justify-content:space-between;align-items:flex-start"><div><div class="small muted">Корпус</div><h3 style="font-size:19px;color:var(--ink)">«${esc(b.name)}»</h3><div class="stars">${'★'.repeat(b.stars)}<span style="color:#ddd">${'★'.repeat(5 - b.stars)}</span></div></div><span class="badge b-ok">${free} своб.</span></div>
          <div class="kv section-gap"><span class="muted">Этажей / комнат на этаже</span><b>${b.floors} / ${b.roomsPerFloor}</b></div>
          <div class="kv"><span class="muted">Всего комнат в корпусе</span><b>${b.floors * b.roomsPerFloor}</b></div>
          <div class="kv"><span class="muted">Базовый тариф</span><b>${money(b.base)}</b></div></div>`;
      }).join('');
      return `<div class="grid grid-3">${bcards}</div>
        <div class="alert alert-info section-gap">${icon('info')}<div>Тариф рассчитывается автоматически: <b>базовый тариф корпуса × коэффициент категории</b> (Стандарт 1,0 · Комфорт 1,4 · Люкс 2,2) <b>× коэффициент вместимости</b> (1-местн. 0,8 · 2-местн. 1,0 · 3-местн. 1,25). В макете показана выборка номеров по корпусам.</div></div>
        <div class="card section-gap">
          <div class="toolbar">
            <div class="search">${icon('search')}<input class="input" id="f-q" placeholder="Номер комнаты…" maxlength="10"></div>
            <select class="input" id="f-b"><option value="">Все корпуса</option>${db.buildings.map((b) => opt(b.id, '«' + b.name + '»')).join('')}</select>
            <select class="input" id="f-c"><option value="">Все категории</option>${Object.keys(CATEGORIES).map((c) => opt(c, c)).join('')}</select>
            <select class="input" id="f-s"><option value="">Любой статус</option>${opt('free', 'Свободен')}${opt('occ', 'Занят')}${opt('res', 'Забронирован')}</select>
            <span class="count" id="f-count"></span>
          </div>
          <div class="table-wrap"><table class="table"><thead><tr><th>Корпус</th><th>Номер</th><th>Этаж</th><th>Категория</th><th>Мест</th><th class="right">Тариф / сутки</th><th>Статус на ${fmtDate(TODAY)}</th><th>Освобождается</th></tr></thead><tbody id="rooms-body"></tbody></table></div>
        </div>`;
    },
    mount() {
      const draw = () => {
        const q = $('#f-q').value.trim(), b = $('#f-b').value, c = $('#f-c').value, s = $('#f-s').value;
        const rows = App.db.rooms.filter((r) => (!q || r.number.includes(q)) && (!b || r.buildingId === b) && (!c || r.category === c) && (!s || roomState(r).key === s));
        $('#f-count').textContent = `Найдено: ${rows.length}`;
        $('#rooms-body').innerHTML = rows.map((r) => {
          const st = roomState(r);
          return `<tr><td>«${esc(bldById(r.buildingId).name)}»</td><td><b>${esc(r.number)}</b></td><td>${r.floor}</td><td>${esc(r.category)}</td><td>${r.capacity}</td><td class="right nowrap">${money(tariff(App.db, r))}</td><td><span class="badge ${st.cls}">${st.label}</span></td><td class="small muted">${st.bk ? fmtDate(st.bk.checkOut) : '—'}</td></tr>`;
        }).join('') || '<tr><td colspan="8" class="empty">Ничего не найдено</td></tr>';
      };
      ['#f-q', '#f-b', '#f-c', '#f-s'].forEach((s) => $(s).addEventListener('input', draw));
      draw();
    },
  };

  /* ---------- Гости: список ---------- */
  PAGES.guests = {
    title: 'Гости',
    crumbs: () => 'Операции · реестр клиентов',
    render() {
      return `<div class="alert alert-warn">${icon('masks')}<div><b>Персональные данные маскируются</b>Паспорт, телефон, e-mail и дата рождения показаны частично (152-ФЗ, принцип минимизации). Полные данные раскрываются только в карточке гостя ролью «Администратор рецепции» с указанием цели и записью в журнал.</div></div>
        <div class="card section-gap">
          <div class="toolbar">
            <div class="search">${icon('search')}<input class="input" id="g-q" placeholder="Фамилия, имя или последние 4 цифры паспорта…" maxlength="40"></div>
            <select class="input" id="g-f">${opt('', 'Все гости')}${opt('inhouse', 'Проживают сейчас')}${opt('upcoming', 'Ожидаются')}${opt('debt', 'С задолженностью')}${opt('corp', 'Корпоративные')}</select>
            <span class="count" id="g-count"></span>
            <div class="spacer"></div>
            ${can('editGuest') ? `<button class="btn btn-primary" data-action="guest-new">${icon('plus')} Новый гость</button>` : ''}
          </div>
          <div class="table-wrap"><table class="table"><thead><tr><th>ФИО</th><th>Паспорт</th><th>Телефон</th><th>Броней</th><th>Статус</th><th class="right">Задолженность</th><th></th></tr></thead><tbody id="g-body"></tbody></table></div>
        </div>`;
    },
    mount() {
      const draw = () => {
        const q = $('#g-q').value.trim().toLowerCase(), f = $('#g-f').value;
        const rows = App.db.guests.filter((g) => {
          const bks = App.db.bookings.filter((b) => b.guestId === g.id);
          const textOk = !q || fullName(g).toLowerCase().includes(q) || (/^\d{4}$/.test(q) && g.passport.replace(/\D/g, '').endsWith(q));
          const fOk = !f || (f === 'inhouse' && bks.some((b) => b.status === 'Заселён')) || (f === 'upcoming' && bks.some((b) => b.status === 'Забронировано')) || (f === 'debt' && bks.some((b) => debtOf(b) > 0)) || (f === 'corp' && bks.some((b) => b.companyId));
          return textOk && fOk;
        }).sort((a, b) => a.lastName.localeCompare(b.lastName, 'ru'));
        $('#g-count').textContent = `Найдено: ${rows.length}`;
        $('#g-body').innerHTML = rows.map((g) => {
          const bks = App.db.bookings.filter((b) => b.guestId === g.id);
          const d = bks.reduce((s, b) => s + debtOf(b), 0);
          const st = bks.some((b) => b.status === 'Заселён') ? '<span class="badge b-info">Проживает</span>' : bks.some((b) => b.status === 'Забронировано') ? '<span class="badge b-warn">Ожидается</span>' : '<span class="badge">Нет активных</span>';
          return `<tr class="clickable" data-href="#guest/${g.id}"><td><b>${esc(fullName(g))}</b></td><td class="mono">${esc(mask.passport(g.passport))}</td><td class="mono">${esc(mask.phone(g.phone))}</td><td>${bks.length}</td><td>${st}</td><td class="right ${d ? 'chain-bad' : ''}"><b>${d ? money(d) : '—'}</b></td><td class="right"><a class="btn btn-sm" href="#guest/${g.id}">Карточка</a></td></tr>`;
        }).join('') || '<tr><td colspan="7" class="empty">Гости не найдены</td></tr>';
      };
      $('#g-q').addEventListener('input', draw); $('#g-f').addEventListener('input', draw);
      draw();
    },
  };

  /* ---------- Гости: карточка ---------- */
  let revealed = null;
  PAGES.guest = {
    title: () => 'Карточка гостя',
    crumbs: () => '<a href="#guests">Гости</a> · карточка',
    render(r) {
      const g = guestById(r.id);
      if (!g) return `<div class="card denied"><div class="code">404</div><h2>Гость не найден</h2><a class="btn" href="#guests">К списку</a></div>`;
      const show = revealed && revealed.id === g.id;
      const bks = App.db.bookings.filter((b) => b.guestId === g.id).sort((a, b) => b.checkIn.localeCompare(a.checkIn));
      const debt = bks.reduce((s, b) => s + debtOf(b), 0);
      const pdTag = `<span class="pd-tag">${icon('lock')} ПДн</span>`;
      const pdv = (full, masked) => `<span class="pd-value"><span class="mono">${esc(show ? full : masked)}</span>${pdTag}</span>`;
      return `<a class="btn btn-sm btn-ghost no-print" href="#guests" style="margin-bottom:12px">${icon('back')} К списку гостей</a>
      <div class="grid grid-21">
        <div class="card">
          <div class="profile-head"><div class="avatar">${esc(g.lastName[0] + g.firstName[0])}</div><div style="flex:1"><h2>${esc(fullName(g))}</h2><div class="small muted">ID ${esc(g.id)} · в базе с ${fmtDate(g.created)}</div></div>
            <div style="display:flex;gap:8px;flex-wrap:wrap;justify-content:flex-end">
              ${can('revealPD') ? (show ? `<button class="btn btn-sm" data-action="pd-hide">${icon('eyeoff')} Скрыть <span class="reveal-timer" id="reveal-left"></span></button>` : `<button class="btn btn-sm btn-gold" data-action="pd-reveal" data-id="${g.id}">${icon('eye')} Показать ПДн</button>`) : ''}
              ${can('editGuest') ? `<button class="btn btn-sm" data-action="guest-edit" data-id="${g.id}">${icon('edit')} Изменить</button><button class="btn btn-sm" data-action="guest-delete" data-id="${g.id}" title="Удалить">${icon('trash')}</button>` : ''}
            </div></div>
          <div class="dl">
            <div>Фамилия Имя Отчество</div><div><b>${esc(fullName(g))}</b></div>
            <div>Дата рождения</div><div>${pdv(fmtDate(g.birth), mask.birth(g.birth))}</div>
            <div>Паспорт (серия, номер)</div><div>${pdv(g.passport, mask.passport(g.passport))}</div>
            <div>Телефон</div><div>${pdv(g.phone, mask.phone(g.phone))}</div>
            <div>E-mail</div><div>${pdv(g.email || '—', mask.email(g.email))}</div>
            <div>Согласие на обработку ПДн</div><div><span class="badge b-ok">получено ${fmtDate(g.consent)}</span> <span class="small muted">ст. 9 152-ФЗ</span></div>
          </div>
          ${!can('revealPD') ? `<div class="card-body" style="border-top:1px solid var(--line)"><div class="alert alert-info">${icon('info')}<div>Для роли «${esc(ROLES[App.user.role].name)}» полные персональные данные недоступны — достаточно маскированного вида для выполнения обязанностей.</div></div></div>` : show ? `<div class="card-body" style="border-top:1px solid var(--line)"><div class="alert alert-warn">${icon('eye')}<div>Данные раскрыты с целью «${esc(revealed.reason)}». Просмотр записан в журнал. Данные будут автоматически скрыты.</div></div></div>` : ''}
        </div>
        <div class="card"><div class="card-head"><h3>Лицевой счёт</h3></div><div class="card-body" style="padding-top:6px">
          <div class="kv"><span>Всего бронирований</span><b>${bks.length}</b></div>
          <div class="kv"><span>Начислено (проживание)</span><b>${money(bks.filter((b) => b.status !== 'Отменено').reduce((s, b) => s + b.cost, 0))}</b></div>
          <div class="kv"><span>Доп. услуги</span><b>${money(bks.reduce((s, b) => s + chargesOf(App.db, b.id), 0))}</b></div>
          <div class="kv"><span>Оплачено</span><b>${money(bks.reduce((s, b) => s + b.paid, 0))}</b></div>
          <div class="kv"><span>Задолженность</span><b class="${debt ? 'chain-bad' : 'chain-ok'}">${money(debt)}</b></div>
        </div></div>
      </div>
      <div class="card section-gap"><div class="card-head"><h3>История проживания</h3><div class="spacer"></div>${can('editBooking') ? `<a class="btn btn-sm btn-primary" href="#booking/new?guest=${g.id}">${icon('plus')} Забронировать</a>` : ''}</div>
        <div class="table-wrap"><table class="table"><thead><tr><th>№</th><th>Номер</th><th>Заезд</th><th>Выезд</th><th>Организация</th><th class="right">Стоимость</th><th>Статус</th></tr></thead><tbody>
        ${bks.map((b) => `<tr><td class="mono">${b.id}</td><td>${esc(roomLabel(roomById(b.roomId)))}</td><td>${fmtDate(b.checkIn)}</td><td>${fmtDate(b.checkOut)}</td><td class="small">${b.companyId ? esc(compById(b.companyId).name) : '<span class="muted">частное лицо</span>'}</td><td class="right">${money(b.cost)}</td><td>${statusBadge(b.status)}</td></tr>`).join('') || '<tr><td colspan="7" class="empty">Нет бронирований</td></tr>'}
        </tbody></table></div></div>`;
    },
    mount(r) {
      if (revealed && revealed.id === r.id) {
        const tick = () => {
          const left = Math.ceil((revealed.until - Date.now()) / 1000);
          if (left <= 0) { revealed = null; render(); toast('Персональные данные снова скрыты', 'ok'); return; }
          const el = $('#reveal-left'); if (el) el.textContent = `(${left} с)`;
        };
        tick();
        revealTimer = setInterval(tick, 1000);
      } else if (revealed) revealed = null;
    },
  };

  function guestForm(g) {
    const isNew = !g;
    g = g || { lastName: '', firstName: '', middleName: '', birth: '', passport: '', phone: '', email: '' };
    openModal(`
      <div class="modal-head"><div class="m-ico">${icon('users')}</div><div><h3>${isNew ? 'Регистрация нового гостя' : 'Изменение карточки гостя'}</h3><p>Поля, отмеченные <span style="color:var(--bad)">*</span>, обязательны. Данные проверяются перед сохранением.</p></div></div>
      <form class="modal-body" id="guest-form" novalidate autocomplete="off">
        <div class="form-grid">
          <div class="field"><label>Фамилия<span class="req">*</span></label><input class="input" id="gf-last" value="${esc(g.lastName)}" maxlength="40"><div class="err"></div></div>
          <div class="field"><label>Имя<span class="req">*</span></label><input class="input" id="gf-first" value="${esc(g.firstName)}" maxlength="40"><div class="err"></div></div>
          <div class="field"><label>Отчество</label><input class="input" id="gf-mid" value="${esc(g.middleName)}" maxlength="40"><div class="err"></div></div>
          <div class="field"><label>Дата рождения<span class="req">*</span></label><input class="input" type="date" id="gf-birth" value="${esc(g.birth)}" max="${TODAY}"><div class="err"></div></div>
          <div class="field"><label>Паспорт: серия и номер<span class="req">*</span></label><input class="input mono" id="gf-pass" value="${esc(g.passport)}" placeholder="0000 000000" inputmode="numeric" maxlength="11"><div class="hint">Формат: 4 цифры серии, пробел, 6 цифр номера</div><div class="err"></div></div>
          <div class="field"><label>Телефон<span class="req">*</span></label><input class="input mono" id="gf-phone" value="${esc(g.phone)}" placeholder="+7 (000) 000-00-00" inputmode="tel" maxlength="18"><div class="err"></div></div>
          <div class="field span-2"><label>E-mail</label><input class="input" id="gf-email" value="${esc(g.email)}" maxlength="60" placeholder="name@example.ru"><div class="err"></div></div>
          ${isNew ? `<div class="field span-2"><label class="checkbox"><input type="checkbox" id="gf-consent"><span>Гость дал письменное согласие на обработку персональных данных (ст. 9 152-ФЗ)<span class="req" style="color:var(--bad)">*</span></span></label><div class="err" id="gf-consent-err"></div></div>` : ''}
        </div>
      </form>
      <div class="modal-foot"><button class="btn" data-action="modal-cancel">Отмена</button><button class="btn btn-primary" id="gf-save">${icon('check')} Сохранить</button></div>`, { wide: true });
    // Маска ввода паспорта и телефона
    $('#gf-pass').addEventListener('input', (e) => { const d = e.target.value.replace(/\D/g, '').slice(0, 10); e.target.value = d.length > 4 ? d.slice(0, 4) + ' ' + d.slice(4) : d; });
    $('#gf-phone').addEventListener('input', (e) => {
      let d = e.target.value.replace(/\D/g, ''); if (d.startsWith('8') || d.startsWith('7')) d = d.slice(1); d = d.slice(0, 10);
      let s = '+7'; if (d.length) s += ' (' + d.slice(0, 3); if (d.length >= 3) s += ')'; if (d.length > 3) s += ' ' + d.slice(3, 6); if (d.length > 6) s += '-' + d.slice(6, 8); if (d.length > 8) s += '-' + d.slice(8, 10);
      e.target.value = s;
    });
    $('#gf-save').addEventListener('click', () => {
      const v = { lastName: $('#gf-last').value.trim(), firstName: $('#gf-first').value.trim(), middleName: $('#gf-mid').value.trim(), birth: $('#gf-birth').value, passport: $('#gf-pass').value.trim(), phone: $('#gf-phone').value.trim(), email: $('#gf-email').value.trim() };
      const nameRe = /^[А-ЯЁ][а-яё]+(-[А-ЯЁ][а-яё]+)?$/;
      let ok = true;
      const chk = (id, msg) => { setErr(id, msg); if (msg) ok = false; };
      chk('gf-last', !v.lastName ? 'Обязательное поле' : !nameRe.test(v.lastName) ? 'Кириллица, с заглавной буквы' : '');
      chk('gf-first', !v.firstName ? 'Обязательное поле' : !nameRe.test(v.firstName) ? 'Кириллица, с заглавной буквы' : '');
      chk('gf-mid', v.middleName && !nameRe.test(v.middleName) ? 'Кириллица, с заглавной буквы' : '');
      const age = v.birth && isValidISO(v.birth) ? daysBetween(v.birth, TODAY) / 365.25 : -1;
      chk('gf-birth', !v.birth ? 'Укажите дату рождения' : !isValidISO(v.birth) ? 'Некорректная дата (ДД.ММ.ГГГГ)' : age < 14 ? 'Паспорт РФ выдаётся с 14 лет' : age > 120 ? 'Проверьте год рождения' : '');
      const dup = App.db.guests.find((x) => x.passport === v.passport && (!g.id || x.id !== g.id));
      chk('gf-pass', !/^\d{4} \d{6}$/.test(v.passport) ? 'Формат: 0000 000000' : dup ? 'Гость с таким паспортом уже есть в базе' : '');
      chk('gf-phone', !/^\+7 \(\d{3}\) \d{3}-\d{2}-\d{2}$/.test(v.phone) ? 'Формат: +7 (000) 000-00-00' : '');
      chk('gf-email', v.email && !/^[^\s@]+@[^\s@]+\.[a-zа-я]{2,}$/i.test(v.email) ? 'Некорректный e-mail' : '');
      if (isNew) { const c = $('#gf-consent').checked; $('#gf-consent-err').textContent = c ? '' : 'Без согласия регистрация невозможна'; if (!c) ok = false; }
      if (!ok) { toast('Проверьте выделенные поля', 'bad'); return; }
      if (isNew) {
        const id = 'g' + (++App.db.seq.guest);
        App.db.guests.push(Object.assign({ id, consent: TODAY, created: TODAY }, v));
        saveDB(); audit('GUEST_CREATE', 'Гость ' + id, 'Успех', 'Зарегистрирован новый гость, согласие на обработку ПДн получено');
        closeModal(id); toast('Гость зарегистрирован');
        if (App.route.page === 'booking') { BookingDraft.guestId = id; render(); } else location.hash = '#guest/' + id;
      } else {
        const changed = Object.keys(v).filter((k) => v[k] !== g[k]);
        Object.assign(g, v); saveDB();
        audit('GUEST_UPDATE', 'Гость ' + g.id, 'Успех', 'Изменены поля: ' + (changed.join(', ') || 'нет'));
        closeModal(); toast('Изменения сохранены'); render();
      }
    });
  }

  /* ---------- Бронирования: список ---------- */
  PAGES.bookings = {
    title: 'Бронирования',
    crumbs: () => 'Операции',
    render(r) {
      const p = r.params;
      return `<div class="card">
          <div class="toolbar">
            <div class="search">${icon('search')}<input class="input" id="b-q" placeholder="№ брони или фамилия гостя…" maxlength="40" value="${esc(p.q || '')}"></div>
            <select class="input" id="b-s"><option value="">Все статусы</option>${BOOKING_STATUSES.map((s) => opt(s, s, p.s)).join('')}</select>
            <select class="input" id="b-b"><option value="">Все корпуса</option>${App.db.buildings.map((b) => opt(b.id, '«' + b.name + '»', p.b)).join('')}</select>
            <div class="spacer"></div>
            ${can('editBooking') ? `<a class="btn btn-primary" href="#booking/new">${icon('plus')} Новое бронирование</a>` : ''}
          </div>
          <div class="toolbar" style="background:var(--surface-2)">
            <span class="small" style="font-weight:700;color:var(--ink-3)">${icon('filter')} Запрос «Бронирования за период»:</span>
            <span class="small muted">с</span><input class="input" type="date" id="b-from" style="width:auto" value="${esc(p.from || '')}">
            <span class="small muted">по</span><input class="input" type="date" id="b-to" style="width:auto" value="${esc(p.to || '')}">
            <button class="btn btn-sm" data-action="period-preset" data-days="7">7 дней</button>
            <button class="btn btn-sm" data-action="period-preset" data-days="30">30 дней</button>
            <button class="btn btn-sm btn-ghost" data-action="period-clear">Сбросить</button>
            <div class="spacer"></div><span class="count" id="b-count"></span>
          </div>
          <div class="table-wrap"><table class="table"><thead><tr><th>№</th><th>Гость</th><th>Номер</th><th>Заезд</th><th>Выезд</th><th>Ночей</th><th>Организация</th><th class="right">Стоимость</th><th>Статус</th><th></th></tr></thead><tbody id="b-body"></tbody></table></div>
          <div class="toolbar" style="border-top:1px solid var(--line);border-bottom:0" id="b-total"></div>
        </div>`;
    },
    mount() {
      const draw = () => {
        const q = $('#b-q').value.trim().toLowerCase(), s = $('#b-s').value, b = $('#b-b').value, from = $('#b-from').value, to = $('#b-to').value;
        const rows = App.db.bookings.filter((bk) => {
          const g = guestById(bk.guestId), room = roomById(bk.roomId);
          return (!q || bk.id.toLowerCase().includes(q) || (g && g.lastName.toLowerCase().includes(q)))
            && (!s || bk.status === s) && (!b || room.buildingId === b)
            && (!from || bk.checkOut > from) && (!to || bk.checkIn <= to);
        }).sort((a, b2) => b2.checkIn.localeCompare(a.checkIn));
        $('#b-count').textContent = `Найдено: ${rows.length}`;
        $('#b-body').innerHTML = rows.map((bk) => {
          const g = guestById(bk.guestId);
          const acts = can('editBooking') ? `<div class="actions"><a class="btn btn-sm btn-icon" href="#booking/${bk.id}" title="Изменить">${icon('edit')}</a>${isActive(bk) ? `<button class="btn btn-sm btn-icon" data-action="booking-cancel" data-id="${bk.id}" title="Отменить бронь">${icon('x')}</button>` : ''}<button class="btn btn-sm btn-icon" data-action="booking-delete" data-id="${bk.id}" title="Удалить">${icon('trash')}</button></div>` : '';
          return `<tr><td class="mono">${bk.id}</td><td>${App.user.role === 'director' ? esc(shortName(g)) : `<a href="#guest/${g.id}">${esc(shortName(g))}</a>`}</td><td class="nowrap">${esc(roomLabel(roomById(bk.roomId)))}</td><td class="nowrap">${fmtDate(bk.checkIn)}</td><td class="nowrap">${fmtDate(bk.checkOut)}</td><td>${daysBetween(bk.checkIn, bk.checkOut)}</td><td class="small">${bk.companyId ? esc(compById(bk.companyId).name) : '<span class="muted">—</span>'}</td><td class="right nowrap">${money(bk.cost)}</td><td>${statusBadge(bk.status)}</td><td>${acts}</td></tr>`;
        }).join('') || '<tr><td colspan="10" class="empty">Бронирований не найдено</td></tr>';
        const sum = rows.filter((x) => x.status !== 'Отменено').reduce((a, x) => a + x.cost, 0);
        $('#b-total').innerHTML = `<span class="small muted">Итого по выборке (без отменённых):</span> <b>${money(sum)}</b>${from || to ? `<span class="small muted">· период ${from ? fmtDate(from) : '…'} — ${to ? fmtDate(to) : '…'}</span>` : ''}`;
      };
      ['#b-q', '#b-s', '#b-b', '#b-from', '#b-to'].forEach((s) => $(s).addEventListener('input', draw));
      PAGES.bookings.redraw = draw;
      draw();
    },
  };

  /* ---------- Бронирование: форма ввода / редактирования ---------- */
  const BookingDraft = {};
  PAGES.booking = {
    title: (r) => r.id === 'new' ? 'Новое бронирование' : 'Бронирование ' + r.id,
    crumbs: () => '<a href="#bookings">Бронирования</a> · форма',
    render(r) {
      const isNew = r.id === 'new';
      const bk = isNew ? null : App.db.bookings.find((b) => b.id === r.id);
      if (!isNew && !bk) return `<div class="card denied"><div class="code">404</div><h2>Бронирование не найдено</h2><a class="btn" href="#bookings">К списку</a></div>`;
      const src = bk || {};
      const d = Object.assign({ guestId: r.params.guest || '', buildingId: '', roomId: '', checkIn: '', checkOut: '', persons: 1, companyId: '', status: 'Забронировано', note: '' }, src, BookingDraft.key === r.id ? BookingDraft : {});
      if (d.roomId && !d.buildingId) d.buildingId = roomById(d.roomId).buildingId;
      const guests = App.db.guests.slice().sort((a, b) => a.lastName.localeCompare(b.lastName, 'ru'));
      return `<div class="grid grid-21">
        <div class="card"><div class="card-head"><h3>${isNew ? 'Ввод нового бронирования' : 'Редактирование ' + esc(bk.id)}</h3></div>
        <form class="card-body" id="bk-form" novalidate autocomplete="off">
          <div class="form-grid">
            <div class="field span-2"><label>Гость<span class="req">*</span></label>
              <div style="display:flex;gap:8px"><select class="input" id="bk-guest"><option value="">— выберите гостя из базы —</option>${guests.map((g) => opt(g.id, `${fullName(g)} · паспорт ${mask.passport(g.passport)}`, d.guestId)).join('')}</select>
              <button type="button" class="btn" data-action="guest-new" title="Зарегистрировать нового гостя">${icon('plus')}</button></div><div class="err"></div></div>
            <div class="field"><label>Корпус<span class="req">*</span></label><select class="input" id="bk-building"><option value="">— корпус —</option>${App.db.buildings.map((b) => opt(b.id, `«${b.name}» ${'★'.repeat(b.stars)}`, d.buildingId)).join('')}</select><div class="err"></div></div>
            <div class="field"><label>Номер<span class="req">*</span></label><select class="input" id="bk-room"></select><div class="err"></div></div>
            <div class="field"><label>Дата заезда<span class="req">*</span></label><input class="input" type="date" id="bk-in" value="${esc(d.checkIn)}"><div class="err"></div></div>
            <div class="field"><label>Дата выезда<span class="req">*</span></label><input class="input" type="date" id="bk-out" value="${esc(d.checkOut)}"><div class="err"></div></div>
            <div class="field"><label>Количество гостей<span class="req">*</span></label><select class="input" id="bk-persons" data-val="${esc(d.persons)}"></select><div class="err"></div></div>
            <div class="field"><label>Организация (договор)</label><select class="input" id="bk-company"><option value="">Частное лицо</option>${App.db.companies.map((c) => opt(c.id, `${c.name} — скидка ${c.discount}%`, d.companyId)).join('')}</select><div class="err"></div></div>
            <div class="field"><label>Статус<span class="req">*</span></label><select class="input" id="bk-status">${BOOKING_STATUSES.map((s) => opt(s, s, d.status)).join('')}</select><div class="err"></div></div>
            <div class="field"><label>&nbsp;</label><div class="hint" style="padding-top:10px">Даты выбираются в календаре — ручной ввод в произвольном формате исключён.</div></div>
            <div class="field span-2"><label>Примечание</label><textarea class="input" id="bk-note" maxlength="300" placeholder="Пожелания гостя, особые условия…">${esc(d.note)}</textarea><div class="hint"><span id="bk-note-len">0</span> / 300</div><div class="err"></div></div>
          </div>
        </form>
        <div class="modal-foot" style="border-radius:0 0 var(--radius) var(--radius)"><a class="btn" href="#bookings">Отмена</a><button class="btn btn-primary" id="bk-save">${icon('check')} ${isNew ? 'Создать бронирование' : 'Сохранить изменения'}</button></div>
        </div>
        <div>
          <div class="card"><div class="card-head"><h3>Расчёт стоимости</h3></div><div class="card-body" style="padding-top:6px" id="bk-calc"></div></div>
          <div id="bk-warn" class="section-gap"></div>
        </div>
      </div>`;
    },
    mount(r) {
      const isNew = r.id === 'new';
      const bk = isNew ? null : App.db.bookings.find((b) => b.id === r.id);
      if (!isNew && !bk) return;
      const fillRooms = (keep) => {
        const bId = $('#bk-building').value;
        const rooms = App.db.rooms.filter((x) => x.buildingId === bId);
        $('#bk-room').innerHTML = `<option value="">${bId ? '— номер —' : 'сначала выберите корпус'}</option>` + rooms.map((x) => opt(x.id, `№ ${x.number} · ${x.floor} эт. · ${x.category} · ${x.capacity}-местн. · ${money(tariff(App.db, x))}`, keep)).join('');
        $('#bk-room').disabled = !bId;
      };
      const fillPersons = () => {
        const room = roomById($('#bk-room').value);
        const cur = $('#bk-persons').value || $('#bk-persons').dataset.val;
        const max = room ? room.capacity : 1;
        $('#bk-persons').innerHTML = Array.from({ length: max }, (_, i) => opt(i + 1, i + 1, Math.min(cur, max))).join('');
      };
      const draft = () => ({ key: r.id, guestId: $('#bk-guest').value, buildingId: $('#bk-building').value, roomId: $('#bk-room').value, checkIn: $('#bk-in').value, checkOut: $('#bk-out').value, persons: +$('#bk-persons').value || 1, companyId: $('#bk-company').value || null, status: $('#bk-status').value, note: $('#bk-note').value.trim() });
      const analyze = (v) => {
        const issues = { errors: {}, warns: [] };
        const room = roomById(v.roomId);
        if (room && isValidISO(v.checkIn) && isValidISO(v.checkOut) && v.checkOut > v.checkIn && v.status !== 'Отменено' && v.status !== 'Выселен') {
          const clash = App.db.bookings.find((b) => b.roomId === v.roomId && b.id !== r.id && isActive(b) && overlaps(v.checkIn, v.checkOut, b.checkIn, b.checkOut));
          if (clash) issues.errors['bk-room'] = `Номер занят: ${clash.id} (${fmtDate(clash.checkIn)} — ${fmtDate(clash.checkOut)})`;
        }
        if (room && v.companyId && isValidISO(v.checkIn) && isValidISO(v.checkOut)) {
          const group = App.db.bookings.filter((b) => b.companyId === v.companyId && b.id !== r.id && isActive(b) && overlaps(v.checkIn, v.checkOut, b.checkIn, b.checkOut)).map((b) => roomById(b.roomId));
          const other = group.filter((x) => x.buildingId !== room.buildingId || x.floor !== room.floor);
          if (group.length && other.length) {
            const places = Array.from(new Set(group.map((x) => `«${bldById(x.buildingId).name}», ${x.floor} эт.`)));
            issues.warns.push(`<b>Контроль компактности размещения группы.</b> Другие участники группы «${esc(compById(v.companyId).name)}» размещены: ${esc(places.join('; '))}. Рекомендуется выбрать номер на том же этаже.`);
          }
        }
        if (v.status === 'Отменено' && bk && bk.status !== 'Отменено' && isValidISO(v.checkIn)) {
          const left = daysBetween(TODAY, v.checkIn);
          issues.warns.push(left < 7 ? `<b>Штрафная отмена.</b> До заезда ${left} ${plural(left, ['день', 'дня', 'дней'])} (менее 7). По условиям договора удерживается стоимость первых суток.` : `<b>Бесплатная отмена.</b> До заезда более 7 дней.`);
        }
        return issues;
      };
      const recalc = () => {
        const v = draft();
        Object.assign(BookingDraft, v);
        const room = roomById(v.roomId);
        const nights = isValidISO(v.checkIn) && isValidISO(v.checkOut) ? daysBetween(v.checkIn, v.checkOut) : 0;
        const comp = v.companyId ? compById(v.companyId) : null;
        const t = room ? tariff(App.db, room) : 0;
        const total = nights > 0 ? Math.round(nights * t * (1 - (comp ? comp.discount : 0) / 100)) : 0;
        $('#bk-calc').innerHTML = `
          <div class="kv"><span>Номер</span><b>${room ? esc(roomLabel(room)) : '—'}</b></div>
          <div class="kv"><span>Тариф за сутки</span><b>${room ? money(t) : '—'}</b></div>
          <div class="kv"><span>Ночей</span><b>${nights > 0 ? nights : '—'}</b></div>
          <div class="kv"><span>Скидка по договору</span><b>${comp ? comp.discount + '%' : '—'}</b></div>
          <div class="kv" style="font-size:16px"><span>Итого к оплате</span><b>${money(total)}</b></div>`;
        const iss = analyze(v);
        $('#bk-warn').innerHTML = iss.warns.map((w) => `<div class="alert alert-warn" style="margin-bottom:10px">${icon('alert')}<div>${w}</div></div>`).join('') + (iss.errors['bk-room'] ? `<div class="alert alert-bad">${icon('x')}<div>${esc(iss.errors['bk-room'])}</div></div>` : '');
        $('#bk-note-len').textContent = $('#bk-note').value.length;
      };
      const d0 = Object.assign({}, bk || {}, BookingDraft.key === r.id ? BookingDraft : {});
      fillRooms(d0.roomId || '');
      fillPersons();
      if (BookingDraft.key !== r.id) { Object.keys(BookingDraft).forEach((k) => delete BookingDraft[k]); BookingDraft.key = r.id; }
      $('#bk-building').addEventListener('change', () => { fillRooms(''); fillPersons(); recalc(); });
      $('#bk-room').addEventListener('change', () => { fillPersons(); recalc(); });
      ['#bk-guest', '#bk-in', '#bk-out', '#bk-persons', '#bk-company', '#bk-status', '#bk-note'].forEach((s) => $(s).addEventListener('input', recalc));
      recalc();

      $('#bk-save').addEventListener('click', async () => {
        const v = draft();
        let ok = true;
        const chk = (id, msg) => { setErr(id, msg); if (msg) ok = false; };
        chk('bk-guest', !v.guestId ? 'Выберите гостя' : '');
        chk('bk-building', !v.buildingId ? 'Выберите корпус' : '');
        chk('bk-in', !v.checkIn ? 'Укажите дату заезда' : !isValidISO(v.checkIn) ? 'Некорректная дата' : (isNew && v.checkIn < TODAY) ? 'Дата заезда не может быть в прошлом' : '');
        const nights = isValidISO(v.checkIn) && isValidISO(v.checkOut) ? daysBetween(v.checkIn, v.checkOut) : 0;
        chk('bk-out', !v.checkOut ? 'Укажите дату выезда' : !isValidISO(v.checkOut) ? 'Некорректная дата' : nights <= 0 ? 'Выезд должен быть позже заезда' : nights > 60 ? 'Не более 60 ночей в одном бронировании' : '');
        const room = roomById(v.roomId);
        const iss = analyze(v);
        chk('bk-room', !v.roomId ? 'Выберите номер' : iss.errors['bk-room'] || '');
        chk('bk-persons', room && v.persons > room.capacity ? 'Превышена вместимость номера' : '');
        chk('bk-status', isNew && (v.status === 'Выселен' || v.status === 'Отменено') ? 'Новое бронирование не может иметь этот статус' : v.status === 'Заселён' && v.checkIn > TODAY ? 'Нельзя заселить до даты заезда' : '');
        if (!ok) { toast('Форма содержит ошибки — исправьте выделенные поля', 'bad'); return; }
        if (iss.warns.some((w) => w.includes('компактности'))) {
          const go = await confirmDanger({ title: 'Нарушена компактность размещения группы', text: 'Участники одной организации окажутся на разных этажах. Сохранить бронирование всё равно?', confirmLabel: 'Сохранить', danger: false });
          if (!go) return;
        }
        const data = { guestId: v.guestId, roomId: v.roomId, companyId: v.companyId, checkIn: v.checkIn, checkOut: v.checkOut, persons: v.persons, status: v.status, note: v.note };
        if (isNew) {
          const id = 'B-' + String(++App.db.seq.booking).padStart(4, '0');
          const nb = Object.assign({ id, paid: 0, created: TODAY }, data);
          nb.cost = calcCost(App.db, nb);
          App.db.bookings.push(nb); saveDB();
          audit('BOOKING_CREATE', 'Бронь ' + id, 'Успех', `${roomLabel(room)}, ${fmtDate(v.checkIn)}–${fmtDate(v.checkOut)}, ${money(nb.cost)}`);
          toast(`Бронирование ${id} создано`);
        } else {
          const changed = Object.keys(data).filter((k) => String(data[k] || '') !== String(bk[k] || ''));
          const wasCancel = v.status === 'Отменено' && bk.status !== 'Отменено';
          Object.assign(bk, data);
          bk.cost = calcCost(App.db, bk);
          if (wasCancel && daysBetween(TODAY, bk.checkIn) < 7) { bk.cost = tariff(App.db, room); bk.note = (bk.note ? bk.note + ' · ' : '') + 'Штраф за позднюю отмену: 1 сутки'; }
          saveDB();
          audit(wasCancel ? 'BOOKING_CANCEL' : 'BOOKING_UPDATE', 'Бронь ' + bk.id, 'Успех', 'Изменены поля: ' + (changed.join(', ') || 'нет'));
          toast('Изменения сохранены');
        }
        Object.keys(BookingDraft).forEach((k) => delete BookingDraft[k]);
        location.hash = '#bookings';
      });
    },
  };

  async function cancelBooking(id) {
    const bk = App.db.bookings.find((b) => b.id === id);
    const left = daysBetween(TODAY, bk.checkIn);
    const fine = left < 7 && bk.status === 'Забронировано';
    const ok = await confirmDanger({ title: `Отменить бронирование ${id}?`, text: `${esc(shortName(guestById(bk.guestId)))}, ${esc(roomLabel(roomById(bk.roomId)))}, заезд ${fmtDate(bk.checkIn)}. ${fine ? `<br><b style="color:var(--bad)">До заезда менее 7 дней — будет начислен штраф в размере стоимости первых суток.</b>` : bk.status === 'Заселён' ? '<br>Гость уже заселён — бронирование будет закрыто.' : '<br>Отмена бесплатная (более 7 дней до заезда).'}`, confirmLabel: 'Отменить бронь' });
    if (!ok) return;
    bk.status = 'Отменено';
    bk.cost = fine ? tariff(App.db, roomById(bk.roomId)) : 0;
    if (fine) bk.note = (bk.note ? bk.note + ' · ' : '') + 'Штраф за позднюю отмену: 1 сутки';
    saveDB(); audit('BOOKING_CANCEL', 'Бронь ' + id, 'Успех', fine ? 'Штрафная отмена (менее 7 дней)' : 'Бесплатная отмена');
    toast(`Бронирование ${id} отменено`); render();
  }
  async function deleteBooking(id) {
    const bk = App.db.bookings.find((b) => b.id === id);
    const hasMoney = bk.paid > 0 || App.db.charges.some((c) => c.bookingId === id);
    if (hasMoney) {
      await confirmDanger({ title: 'Удаление невозможно', text: `По бронированию ${id} есть оплаты или начисления услуг. Для сохранения целостности финансового учёта используйте <b>отмену</b> бронирования.`, confirmLabel: 'Понятно', danger: false });
      return;
    }
    const ok = await confirmDanger({ title: `Удалить бронирование ${id}?`, text: 'Запись будет безвозвратно удалена из базы данных. Действие будет зарегистрировано в журнале.', confirmLabel: 'Удалить', requireText: 'УДАЛИТЬ' });
    if (!ok) return;
    App.db.bookings = App.db.bookings.filter((b) => b.id !== id);
    saveDB(); audit('BOOKING_DELETE', 'Бронь ' + id, 'Успех', `${roomLabel(roomById(bk.roomId))}, ${fmtDate(bk.checkIn)}–${fmtDate(bk.checkOut)}`);
    toast(`Бронирование ${id} удалено`, 'warn'); render();
  }
  async function deleteGuest(id) {
    const g = guestById(id);
    const bks = App.db.bookings.filter((b) => b.guestId === id);
    if (bks.length) {
      await confirmDanger({ title: 'Удаление невозможно', text: `У гостя есть ${bks.length} ${plural(bks.length, ['бронирование', 'бронирования', 'бронирований'])}. Карточка с историей проживания хранится в течение срока, установленного политикой обработки ПДн, после чего обезличивается.`, confirmLabel: 'Понятно', danger: false });
      return;
    }
    const ok = await confirmDanger({ title: 'Удалить карточку гостя?', text: `${esc(fullName(g))}. Персональные данные будут уничтожены (ст. 21 152-ФЗ).`, confirmLabel: 'Удалить', requireText: 'УДАЛИТЬ' });
    if (!ok) return;
    App.db.guests = App.db.guests.filter((x) => x.id !== id);
    saveDB(); audit('GUEST_DELETE', 'Гость ' + id, 'Успех', 'Уничтожение ПДн по запросу субъекта');
    toast('Карточка гостя удалена', 'warn'); location.hash = '#guests';
  }
  function revealPD(id) {
    const g = guestById(id);
    openModal(`
      <div class="modal-head"><div class="m-ico warn">${icon('eye')}</div><div><h3>Раскрытие персональных данных</h3><p>${esc(fullName(g))}. Полные данные будут показаны на ${App.policy.revealSec} секунд. Факт просмотра, цель и время фиксируются в журнале событий.</p></div></div>
      <div class="modal-body"><div class="field"><label>Цель обработки ПДн<span class="req">*</span></label><select class="input" id="pd-reason" autofocus><option value="">— выберите цель —</option>${PD_REASONS.map((x) => opt(x, x)).join('')}</select><div class="err"></div></div></div>
      <div class="modal-foot"><button class="btn" data-action="modal-cancel">Отмена</button><button class="btn btn-gold" id="pd-go">${icon('eye')} Показать</button></div>`);
    $('#pd-go').addEventListener('click', () => {
      const reason = $('#pd-reason').value;
      if (!reason) { setErr('pd-reason', 'Укажите цель — без неё раскрытие ПДн запрещено'); return; }
      revealed = { id, reason, until: Date.now() + App.policy.revealSec * 1000 };
      audit('PD_VIEW', 'Гость ' + id, 'Успех', 'Цель: ' + reason);
      closeModal(); render();
    });
  }

  /* ---------- Лицевые счета ---------- */
  PAGES.accounts = {
    title: 'Лицевые счета',
    crumbs: () => 'Финансы',
    render() {
      const rows = App.db.bookings.filter((b) => b.status !== 'Отменено' || b.cost > 0).sort((a, b) => debtOf(b) - debtOf(a));
      const debt = rows.reduce((s, b) => s + debtOf(b), 0);
      const charges = App.db.charges.slice().sort((a, b) => b.date.localeCompare(a.date) || b.id.localeCompare(a.id)).slice(0, 10);
      return `<div class="grid grid-3">
          ${kpi('Общая задолженность', money(debt), 'money', 'red', `${rows.filter((b) => debtOf(b) > 0).length} лицевых счетов с долгом`)}
          ${kpi('Начислено за проживание', money(rows.reduce((s, b) => s + b.cost, 0)), 'bed', 'blue')}
          ${kpi('Доп. услуги', money(App.db.charges.reduce((s, c) => s + c.amount, 0)), 'list', '', 'питание, досуг, бытовые')}
        </div>
        <div class="card section-gap"><div class="toolbar">
          <label class="checkbox small"><input type="checkbox" id="a-debt"> Только с задолженностью</label>
          <div class="spacer"></div>
          ${can('addCharge') ? `<button class="btn" data-action="charge-new">${icon('plus')} Начислить услугу</button>` : ''}
          ${can('takePayment') ? `<button class="btn btn-primary" data-action="payment-new">${icon('wallet')} Принять оплату</button>` : ''}
        </div>
        <div class="table-wrap"><table class="table"><thead><tr><th>Счёт / бронь</th><th>Гость</th><th>Номер</th><th>Статус</th><th class="right">Проживание</th><th class="right">Услуги</th><th class="right">Оплачено</th><th class="right">Долг</th></tr></thead><tbody id="a-body">
        ${rows.map((b) => { const d = debtOf(b); return `<tr data-debt="${d > 0 ? 1 : 0}"><td class="mono">${b.id}</td><td>${esc(shortName(guestById(b.guestId)))}</td><td class="small">${esc(roomLabel(roomById(b.roomId)))}</td><td>${statusBadge(b.status)}</td><td class="right nowrap">${money(b.cost)}</td><td class="right nowrap">${money(chargesOf(App.db, b.id))}</td><td class="right nowrap">${money(b.paid)}</td><td class="right nowrap ${d ? 'chain-bad' : 'chain-ok'}"><b>${d ? money(d) : '0 ₽'}</b></td></tr>`; }).join('')}
        </tbody></table></div></div>
        <div class="card section-gap"><div class="card-head"><h3>Последние начисления услуг</h3></div><div class="table-wrap"><table class="table"><thead><tr><th>№</th><th>Дата</th><th>Бронь</th><th>Категория</th><th>Услуга</th><th>Кол-во</th><th class="right">Сумма</th></tr></thead><tbody>
        ${charges.map((c) => { const s = SERVICES.find((x) => x.id === c.serviceId); return `<tr><td class="mono">${c.id}</td><td>${fmtDate(c.date)}</td><td class="mono">${c.bookingId}</td><td><span class="badge plain b-ink">${esc(s.cat)}</span></td><td>${esc(s.name)}</td><td>${c.qty}</td><td class="right">${money(c.amount)}</td></tr>`; }).join('')}
        </tbody></table></div></div>`;
    },
    mount() {
      $('#a-debt').addEventListener('change', (e) => $$('#a-body tr').forEach((tr) => tr.classList.toggle('hidden', e.target.checked && tr.dataset.debt !== '1')));
    },
  };
  function chargeForm() {
    const open = App.db.bookings.filter((b) => b.status === 'Заселён');
    openModal(`
      <div class="modal-head"><div class="m-ico">${icon('list')}</div><div><h3>Начисление дополнительной услуги</h3><p>Стоимость подставляется из прейскуранта — ручной ввод цены исключён.</p></div></div>
      <div class="modal-body"><div class="form-grid">
        <div class="field span-2"><label>Лицевой счёт (проживающий гость)<span class="req">*</span></label><select class="input" id="ch-bk"><option value="">— выберите —</option>${open.map((b) => opt(b.id, `${b.id} · ${shortName(guestById(b.guestId))} · ${roomLabel(roomById(b.roomId))}`)).join('')}</select><div class="err"></div></div>
        <div class="field span-2"><label>Услуга<span class="req">*</span></label><select class="input" id="ch-s"><option value="">— выберите —</option>${['Бытовые услуги', 'Питание', 'Досуг'].map((c) => `<optgroup label="${c}">${SERVICES.filter((s) => s.cat === c).map((s) => opt(s.id, `${s.name} — ${money(s.price)}`)).join('')}</optgroup>`).join('')}</select><div class="err"></div></div>
        <div class="field"><label>Количество<span class="req">*</span></label><select class="input" id="ch-q">${[1, 2, 3, 4, 5].map((n) => opt(n, n)).join('')}</select><div class="err"></div></div>
        <div class="field"><label>Сумма</label><input class="input" id="ch-sum" disabled value="0 ₽"></div>
      </div></div>
      <div class="modal-foot"><button class="btn" data-action="modal-cancel">Отмена</button><button class="btn btn-primary" id="ch-save">${icon('check')} Начислить</button></div>`);
    const upd = () => { const s = SERVICES.find((x) => x.id === $('#ch-s').value); $('#ch-sum').value = money(s ? s.price * +$('#ch-q').value : 0); };
    $('#ch-s').addEventListener('input', upd); $('#ch-q').addEventListener('input', upd);
    $('#ch-save').addEventListener('click', () => {
      const bId = $('#ch-bk').value, sId = $('#ch-s').value, q = +$('#ch-q').value;
      setErr('ch-bk', bId ? '' : 'Выберите лицевой счёт'); setErr('ch-s', sId ? '' : 'Выберите услугу');
      if (!bId || !sId) return;
      const s = SERVICES.find((x) => x.id === sId);
      const id = 'Н-' + String(++App.db.seq.charge).padStart(4, '0');
      App.db.charges.push({ id, bookingId: bId, serviceId: sId, qty: q, amount: s.price * q, date: TODAY });
      saveDB(); audit('CHARGE_ADD', 'Счёт ' + bId, 'Успех', `${s.name} × ${q} = ${money(s.price * q)}`);
      closeModal(); toast('Услуга начислена на лицевой счёт'); render();
    });
  }
  function paymentForm() {
    const debtors = App.db.bookings.filter((b) => debtOf(b) > 0);
    openModal(`
      <div class="modal-head"><div class="m-ico">${icon('wallet')}</div><div><h3>Приём оплаты</h3><p>Сумма не может превышать задолженность по лицевому счёту.</p></div></div>
      <div class="modal-body"><div class="form-grid">
        <div class="field span-2"><label>Лицевой счёт<span class="req">*</span></label><select class="input" id="pm-bk"><option value="">— выберите —</option>${debtors.map((b) => opt(b.id, `${b.id} · ${shortName(guestById(b.guestId))} · долг ${money(debtOf(b))}`)).join('')}</select><div class="err"></div></div>
        <div class="field"><label>Сумма, ₽<span class="req">*</span></label><input class="input" id="pm-sum" inputmode="decimal" placeholder="0"><div class="err"></div></div>
        <div class="field"><label>Способ оплаты<span class="req">*</span></label><select class="input" id="pm-m">${PAY_METHODS.map((m) => opt(m, m)).join('')}</select><div class="err"></div></div>
      </div></div>
      <div class="modal-foot"><button class="btn" data-action="modal-cancel">Отмена</button><button class="btn btn-primary" id="pm-save">${icon('check')} Провести оплату</button></div>`);
    $('#pm-bk').addEventListener('input', (e) => { const b = App.db.bookings.find((x) => x.id === e.target.value); if (b) $('#pm-sum').value = debtOf(b); });
    $('#pm-save').addEventListener('click', async () => {
      const b = App.db.bookings.find((x) => x.id === $('#pm-bk').value);
      const sum = Number(String($('#pm-sum').value).replace(',', '.').replace(/\s/g, ''));
      setErr('pm-bk', b ? '' : 'Выберите лицевой счёт');
      const sErr = !$('#pm-sum').value ? 'Укажите сумму' : !isFinite(sum) || sum <= 0 ? 'Сумма должна быть положительным числом' : b && sum > debtOf(b) ? `Не более ${money(debtOf(b))}` : '';
      setErr('pm-sum', sErr);
      if (!b || sErr) return;
      const method = $('#pm-m').value;
      const ok = await confirmDanger({ title: 'Подтвердите проведение оплаты', text: `Счёт ${b.id}: <b>${money(sum)}</b>, способ — ${esc(method)}. Проведённую оплату нельзя удалить, только сторнировать.`, confirmLabel: 'Провести', danger: false });
      if (!ok) return;
      b.paid += Math.round(sum); saveDB();
      audit('PAYMENT', 'Счёт ' + b.id, 'Успех', `${money(sum)}, ${method}`);
      toast('Оплата проведена'); render();
    });
  }

  /* ---------- Отзывы и жалобы ---------- */
  PAGES.reviews = {
    title: 'Отзывы и жалобы',
    crumbs: () => 'Маркетинг и качество',
    render() {
      const rv = App.db.reviews;
      const topics = Array.from(new Set(rv.map((r) => r.topic)));
      const byTopic = topics.map((t) => { const x = rv.filter((r) => r.topic === t); return { t, n: x.length, avg: x.reduce((s, r) => s + r.rating, 0) / x.length }; }).sort((a, b) => b.n - a.n);
      return `<div class="grid grid-21">
        <div class="card"><div class="toolbar">
          <select class="input" id="r-t">${opt('', 'Все записи')}${opt('Отзыв', 'Только отзывы')}${opt('Жалоба', 'Только жалобы')}</select>
          <select class="input" id="r-s">${opt('', 'Любой статус')}${opt('Новая', 'Новые жалобы')}${opt('На рассмотрении', 'На рассмотрении')}${opt('Решена', 'Решённые')}</select>
          <div class="spacer"></div>
          ${can('editReview') ? `<button class="btn btn-primary" data-action="review-new">${icon('plus')} Зарегистрировать</button>` : ''}
        </div>
        <div class="table-wrap"><table class="table"><thead><tr><th>№</th><th>Дата</th><th>Тип</th><th>Тема</th><th>Оценка</th><th>Текст</th><th>Статус</th></tr></thead><tbody id="r-body"></tbody></table></div></div>
        <div class="card"><div class="card-head"><h3>Оценки по темам</h3></div><div class="card-body">
          ${byTopic.map((x) => `<div class="bar-row" style="grid-template-columns:100px minmax(0,1fr) 40px"><div class="name small">${esc(x.t)}</div><div class="bar"><i class="res" style="width:${x.avg / 5 * 100}%"></i></div><div class="right small"><b>${x.avg.toFixed(1)}</b></div></div>`).join('')}
          <p class="small muted" style="margin-bottom:0">В отзывах указывается только ФИО в сокращённом виде; контакты гостей маркетологу недоступны.</p>
        </div></div></div>`;
    },
    mount() {
      const draw = () => {
        const t = $('#r-t').value, s = $('#r-s').value;
        const rows = App.db.reviews.filter((r) => (!t || r.type === t) && (!s || r.status === s)).sort((a, b) => b.date.localeCompare(a.date));
        $('#r-body').innerHTML = rows.map((r) => `<tr><td class="mono">${r.id}</td><td class="nowrap">${fmtDate(r.date)}</td><td><span class="badge ${r.type === 'Жалоба' ? 'b-bad' : 'b-ok'}">${esc(r.type)}</span></td><td>${esc(r.topic)}</td><td class="rating nowrap">${'★'.repeat(r.rating)}<span style="color:#ddd">${'★'.repeat(5 - r.rating)}</span></td><td class="small">${esc(r.text)}</td><td>${r.type === 'Жалоба' ? (can('editReview') ? `<select class="input" style="height:32px;min-width:150px" data-review="${r.id}">${['Новая', 'На рассмотрении', 'Решена'].map((x) => opt(x, x, r.status)).join('')}</select>` : `<span class="badge ${r.status === 'Решена' ? 'b-ok' : r.status === 'Новая' ? 'b-bad' : 'b-warn'}">${esc(r.status)}</span>`) : '<span class="muted">—</span>'}</td></tr>`).join('') || '<tr><td colspan="7" class="empty">Нет записей</td></tr>';
        $$('[data-review]').forEach((sel) => sel.addEventListener('change', () => {
          const rv = App.db.reviews.find((x) => x.id === sel.dataset.review);
          const old = rv.status; rv.status = sel.value; saveDB();
          audit('REVIEW_STATUS', 'Жалоба ' + rv.id, 'Успех', `${old} → ${rv.status}`);
          toast('Статус жалобы обновлён');
        }));
      };
      $('#r-t').addEventListener('input', draw); $('#r-s').addEventListener('input', draw);
      draw();
    },
  };
  function reviewForm() {
    const gs = App.db.guests.slice().sort((a, b) => a.lastName.localeCompare(b.lastName, 'ru'));
    openModal(`
      <div class="modal-head"><div class="m-ico">${icon('chat')}</div><div><h3>Регистрация отзыва или жалобы</h3><p>Все поля обязательны.</p></div></div>
      <div class="modal-body"><div class="form-grid">
        <div class="field"><label>Тип<span class="req">*</span></label><select class="input" id="rv-type">${opt('Отзыв', 'Отзыв')}${opt('Жалоба', 'Жалоба')}</select></div>
        <div class="field"><label>Тема<span class="req">*</span></label><select class="input" id="rv-topic">${['Сервис', 'Чистота', 'Цена', 'Питание', 'Номер', 'Шум', 'Размещение', 'Досуг'].map((x) => opt(x, x)).join('')}</select></div>
        <div class="field"><label>Гость<span class="req">*</span></label><select class="input" id="rv-guest"><option value="">— выберите —</option>${gs.map((g) => opt(g.id, shortName(g))).join('')}</select><div class="err"></div></div>
        <div class="field"><label>Оценка<span class="req">*</span></label><select class="input" id="rv-rating">${[5, 4, 3, 2, 1].map((n) => opt(n, '★'.repeat(n) + ' (' + n + ')')).join('')}</select></div>
        <div class="field span-2"><label>Текст<span class="req">*</span></label><textarea class="input" id="rv-text" maxlength="400"></textarea><div class="err"></div></div>
      </div></div>
      <div class="modal-foot"><button class="btn" data-action="modal-cancel">Отмена</button><button class="btn btn-primary" id="rv-save">${icon('check')} Сохранить</button></div>`, { wide: true });
    $('#rv-save').addEventListener('click', () => {
      const v = { type: $('#rv-type').value, topic: $('#rv-topic').value, guestId: $('#rv-guest').value, rating: +$('#rv-rating').value, text: $('#rv-text').value.trim() };
      setErr('rv-guest', v.guestId ? '' : 'Выберите гостя');
      setErr('rv-text', v.text.length < 10 ? 'Не менее 10 символов' : '');
      if (!v.guestId || v.text.length < 10) return;
      const id = 'О-' + String(++App.db.seq.review).padStart(3, '0');
      App.db.reviews.push(Object.assign({ id, date: TODAY, status: v.type === 'Жалоба' ? 'Новая' : null }, v));
      saveDB(); audit('REVIEW_ADD', (v.type === 'Жалоба' ? 'Жалоба ' : 'Отзыв ') + id, 'Успех', v.topic);
      closeModal(); toast('Запись зарегистрирована'); render();
    });
  }

  /* ---------- Отчёты (печатные формы) ---------- */
  PAGES.reports = {
    title: 'Отчёты',
    crumbs: () => 'Печатные формы',
    render(r) {
      const avail = REPORTS.filter((x) => x.roles.includes(App.user.role));
      const cur = avail.find((x) => x.id === r.params.type) || avail[0];
      const from = r.params.from || addDays(TODAY, -30), to = r.params.to || addDays(TODAY, 30);
      const tabs = `<div class="tabs no-print">${avail.map((x) => `<a class="tab ${x.id === cur.id ? 'active' : ''}" href="#reports?type=${x.id}">${esc(x.title)}${x.pd ? ' 🔒' : ''}</a>`).join('')}</div>`;
      const params = `<div class="card no-print" style="margin-bottom:18px"><div class="toolbar" style="border:0">
        ${cur.id === 'bookings' ? `<span class="small muted">Период заезда: с</span><input type="date" class="input" id="rp-from" style="width:auto" value="${from}"><span class="small muted">по</span><input type="date" class="input" id="rp-to" style="width:auto" value="${to}"><button class="btn" data-action="report-apply">${icon('refresh')} Сформировать</button>` : `<span class="small muted">Отчёт формируется на дату ${fmtDate(TODAY)}</span>`}
        <div class="spacer"></div>
        <button class="btn" data-action="report-csv" data-type="${cur.id}">${icon('download')} Экспорт CSV</button>
        <button class="btn btn-primary" data-action="report-print" data-type="${cur.id}">${icon('print')} Печать</button>
      </div></div>`;
      const regNo = 'ОТЧ-' + String(App.db.seq.report + 1).padStart(4, '0');
      const grif = cur.pd
        ? `<div class="grif">Конфиденциально<small>Содержит персональные данные<br>(Федеральный закон № 152-ФЗ)</small><small>Экз. № 1</small></div>`
        : `<div class="grif" style="border-color:var(--ink-3);color:var(--ink-3)">Для служебного пользования<small>Экз. № 1</small></div>`;
      const head = `<div class="stamp"><div class="small">Гостиничный комплекс «Комнатки»<br>АИС «Комнатки» · модуль отчётности<br>Рег. № ${regNo}</div>${grif}</div>`;
      const rows = reportRows(cur.id, from, to);
      const tbl = `<table><thead><tr>${rows.head.map((h) => `<th>${esc(h)}</th>`).join('')}</tr></thead><tbody>${rows.body.map((rw) => `<tr>${rw.map((c) => `<td>${esc(c)}</td>`).join('')}</tr>`).join('') || `<tr><td colspan="${rows.head.length}">Нет данных за выбранный период</td></tr>`}</tbody>${rows.foot ? `<tfoot><tr>${rows.foot.map((c) => `<td>${esc(c)}</td>`).join('')}</tr></tfoot>` : ''}</table>`;
      return tabs + params + `<div class="report-paper">${head}<h2>${esc(cur.title)}</h2><div class="rp-sub">${cur.id === 'bookings' ? `за период с ${fmtDate(from)} по ${fmtDate(to)}` : `по состоянию на ${fmtDate(TODAY)}`}</div>${tbl}
        ${cur.pd ? '<p class="small" style="margin-top:12px">Паспортные данные в отчёте маскированы. Передача отчёта третьим лицам запрещена.</p>' : ''}
        <div class="report-sign"><div><div class="line"></div>Сформировал: ${esc(ROLES[App.user.role].name)}, ${esc(App.user.name)}</div><div><div class="line"></div>Утвердил: руководитель службы</div></div>
        <div class="report-meta">Сформировано в АИС «Комнатки» ${fmtDT(Date.now())} · пользователь ${esc(App.user.login)} · ${esc(App.ws)} · факт формирования и печати регистрируется в журнале событий</div></div>`;
    },
    mount(r) {
      const avail = REPORTS.filter((x) => x.roles.includes(App.user.role));
      const cur = avail.find((x) => x.id === r.params.type) || avail[0];
      audit('REPORT_VIEW', 'Отчёт «' + cur.title + '»', 'Успех', cur.id === 'bookings' ? `Период ${r.params.from || '-30д'} — ${r.params.to || '+30д'}` : 'На текущую дату');
    },
  };
  function reportRows(type, from, to) {
    const db = App.db;
    if (type === 'bookings') {
      const list = db.bookings.filter((b) => b.checkIn >= from && b.checkIn <= to).sort((a, b) => a.checkIn.localeCompare(b.checkIn));
      return {
        head: ['№', 'Гость', 'Паспорт', 'Корпус, номер', 'Заезд', 'Выезд', 'Организация', 'Статус', 'Сумма, ₽'],
        body: list.map((b) => { const g = guestById(b.guestId); return [b.id, shortName(g), g ? mask.passport(g.passport) : '—', roomLabel(roomById(b.roomId)), fmtDate(b.checkIn), fmtDate(b.checkOut), b.companyId ? compById(b.companyId).name : '—', b.status, new Intl.NumberFormat('ru-RU').format(b.cost)]; }),
        foot: ['Итого', `${list.length} записей`, '', '', '', '', '', '', new Intl.NumberFormat('ru-RU').format(list.filter((b) => b.status !== 'Отменено').reduce((s, b) => s + b.cost, 0))],
      };
    }
    if (type === 'occupancy') {
      const body = db.buildings.map((b) => {
        const rs = db.rooms.filter((r) => r.buildingId === b.id);
        const o = rs.filter((r) => roomState(r).key === 'occ').length, rv = rs.filter((r) => roomState(r).key === 'res').length;
        return [`«${b.name}»`, '★'.repeat(b.stars), b.floors, b.floors * b.roomsPerFloor, rs.length, o, rv, rs.length - o - rv, Math.round((o + rv) / rs.length * 100) + '%'];
      });
      const tot = db.rooms.length, o = db.rooms.filter((r) => roomState(r).key === 'occ').length, rv = db.rooms.filter((r) => roomState(r).key === 'res').length;
      return { head: ['Корпус', 'Класс', 'Этажей', 'Комнат в корпусе', 'Номеров в выборке', 'Занято', 'Забронировано', 'Свободно', 'Загрузка'], body, foot: ['Итого', '', '', db.buildings.reduce((s, b) => s + b.floors * b.roomsPerFloor, 0), tot, o, rv, tot - o - rv, Math.round((o + rv) / tot * 100) + '%'] };
    }
    if (type === 'debts') {
      const list = db.bookings.filter((b) => debtOf(b) > 0).sort((a, b) => debtOf(b) - debtOf(a));
      const nf = (n) => new Intl.NumberFormat('ru-RU').format(n);
      return {
        head: ['Счёт', 'Гость', 'Паспорт', 'Номер', 'Статус', 'Проживание', 'Услуги', 'Оплачено', 'Долг, ₽'],
        body: list.map((b) => { const g = guestById(b.guestId); return [b.id, shortName(g), mask.passport(g.passport), roomLabel(roomById(b.roomId)), b.status, nf(b.cost), nf(chargesOf(db, b.id)), nf(b.paid), nf(debtOf(b))]; }),
        foot: ['Итого', `${list.length} счетов`, '', '', '', '', '', '', nf(list.reduce((s, b) => s + debtOf(b), 0))],
      };
    }
    // popularity
    const cats = Object.keys(CATEGORIES).map((c) => {
      const bks = db.bookings.filter((b) => b.status !== 'Отменено' && roomById(b.roomId).category === c);
      return [`Номера: ${c}`, bks.length, bks.reduce((s, b) => s + daysBetween(b.checkIn, b.checkOut), 0) + ' ночей', new Intl.NumberFormat('ru-RU').format(bks.reduce((s, b) => s + b.cost, 0))];
    });
    const svc = SERVICES.map((s) => { const cs = db.charges.filter((c) => c.serviceId === s.id); return [`Услуга: ${s.name}`, cs.length, cs.reduce((a, c) => a + c.qty, 0) + ' ед.', new Intl.NumberFormat('ru-RU').format(cs.reduce((a, c) => a + c.amount, 0))]; }).filter((x) => x[1] > 0).sort((a, b) => b[1] - a[1]);
    return { head: ['Позиция', 'Заказов / броней', 'Объём', 'Выручка, ₽'], body: cats.concat(svc) };
  }

  /* ---------- Журнал событий ---------- */
  let tamperedAt = null;
  PAGES.audit = {
    title: 'Журнал событий',
    crumbs: () => 'Безопасность · только для администратора безопасности',
    render() {
      const users = Array.from(new Set(App.audit.map((e) => e.login)));
      return `<div class="alert alert-info">${icon('shield')}<div><b>Журнал защищён от изменения.</b>Каждая запись содержит SHA-256 хэш, вычисленный от её содержимого и хэша предыдущей записи (цепочка). Изменение или удаление любой записи обнаруживается проверкой целостности. Удаление записей через интерфейс не предусмотрено.</div></div>
        <div id="verify-result" class="section-gap"></div>
        <div class="card section-gap">
          <div class="toolbar">
            <div class="search">${icon('search')}<input class="input" id="l-q" placeholder="Объект или подробности…" maxlength="40"></div>
            <select class="input" id="l-u"><option value="">Все пользователи</option>${users.map((u) => opt(u, u)).join('')}</select>
            <select class="input" id="l-e"><option value="">Все события</option>${Object.keys(EVENTS).map((k) => opt(k, EVENTS[k])).join('')}</select>
            <select class="input" id="l-r"><option value="">Любой результат</option>${opt('Успех', 'Успех')}${opt('Отказ', 'Отказ')}${opt('Предупреждение', 'Предупреждение')}</select>
            <label class="checkbox small"><input type="checkbox" id="l-sec"> Только события ИБ</label>
          </div>
          <div class="toolbar" style="background:var(--surface-2)">
            <button class="btn btn-sm btn-primary" data-action="audit-verify">${icon('shield')} Проверить целостность</button>
            <button class="btn btn-sm" data-action="audit-export">${icon('download')} Экспорт CSV</button>
            <button class="btn btn-sm" data-action="audit-tamper" title="Демонстрация: имитирует подмену записи злоумышленником в обход интерфейса">${icon('alert')} Тест: исказить запись</button>
            <div class="spacer"></div><span class="count" id="l-count"></span>
          </div>
          <div class="table-wrap"><table class="table"><thead><tr><th>№</th><th>Дата и время</th><th>Пользователь</th><th>Роль</th><th>АРМ</th><th>Событие</th><th>Объект</th><th>Результат</th><th>Подробности</th><th>Хэш</th></tr></thead><tbody id="l-body"></tbody></table></div>
        </div>`;
    },
    mount() {
      const draw = () => {
        const q = $('#l-q').value.trim().toLowerCase(), u = $('#l-u').value, ev = $('#l-e').value, res = $('#l-r').value, sec = $('#l-sec').checked;
        const rows = App.audit.filter((e) => (!q || (e.object + ' ' + e.details).toLowerCase().includes(q)) && (!u || e.login === u) && (!ev || e.event === ev) && (!res || e.result === res) && (!sec || SECURITY_EVENTS.includes(e.event))).slice().reverse();
        $('#l-count').textContent = `Записей: ${rows.length} из ${App.audit.length}`;
        $('#l-body').innerHTML = rows.slice(0, 300).map((e) => `<tr class="${tamperedAt && e.n === tamperedAt ? 'tampered' : ''}"><td class="mono">${e.n}</td><td class="nowrap small">${fmtDT(e.ts)}</td><td><b>${esc(e.login)}</b></td><td class="small">${esc(e.role)}</td><td class="small nowrap muted">${esc(e.ws.split(' / ')[0])}</td><td class="ev">${esc(EVENTS[e.event] || e.event)}</td><td class="small">${esc(e.object)}</td><td>${resultBadge(e.result)}</td><td class="small">${esc(e.details)}</td><td class="hash" title="${esc(e.hash)}">${esc(e.hash.slice(0, 10))}…</td></tr>`).join('') || '<tr><td colspan="10" class="empty">Нет записей</td></tr>';
      };
      ['#l-q', '#l-u', '#l-e', '#l-r', '#l-sec'].forEach((s) => $(s).addEventListener('input', draw));
      PAGES.audit.redraw = draw;
      draw();
    },
  };
  function showVerify() {
    const v = verifyAudit();
    tamperedAt = v.ok ? null : v.n;
    if (v.ok) audit('AUDIT_VERIFY', 'Журнал событий', 'Успех', `Проверено записей: ${v.n}, нарушений нет`);
    else audit('AUDIT_VERIFY', 'Журнал событий', 'Предупреждение', `Нарушение цепочки хэшей в записи № ${v.n}`);
    render();
    $('#verify-result').innerHTML = v.ok
      ? `<div class="alert alert-ok">${icon('check')}<div><b>Целостность журнала подтверждена.</b>Проверено ${v.n} записей: все хэши и связи цепочки корректны.</div></div>`
      : `<div class="alert alert-bad">${icon('alert')}<div><b>Обнаружено нарушение целостности журнала!</b>Запись № ${v.n} изменена после регистрации (хэш не совпадает). Необходимо провести разбирательство инцидента и восстановить журнал из резервной копии.</div></div>`;
  }

  /* ---------- Учётные записи ---------- */
  PAGES.users = {
    title: 'Учётные записи',
    crumbs: () => 'Безопасность',
    render() {
      return `<div class="card"><div class="card-head"><h3>Пользователи системы</h3><div class="spacer"></div><span class="small muted">Порог блокировки: ${App.policy.maxAttempts} попыток, ${App.policy.lockMin} мин</span></div>
        <div class="table-wrap"><table class="table"><thead><tr><th>Логин</th><th>Сотрудник</th><th>Роль</th><th>Последний вход</th><th>Неудачные попытки</th><th>Состояние</th><th class="right">Действия</th></tr></thead><tbody>
        ${App.users.map((u) => {
          const l = lockOf(u.login), locked = isLocked(u.login);
          const state = u.disabled ? '<span class="badge b-bad">Отключена</span>' : locked ? `<span class="badge b-bad">Заблокирована до ${fmtDT(l.lockedUntil).slice(11, 16)}</span>` : '<span class="badge b-ok">Активна</span>';
          return `<tr><td class="mono"><b>${esc(u.login)}</b></td><td>${esc(u.name)}</td><td><span class="badge plain b-ink">${esc(ROLES[u.role].name)}</span></td><td class="small">${u.lastLogin ? fmtDT(u.lastLogin) : '—'}</td><td>${l.failed || 0}${l.lastFail ? `<span class="small muted"> · ${fmtDT(l.lastFail).slice(11, 16)}</span>` : ''}</td><td>${state}</td><td><div class="actions">
            ${locked || l.failed ? `<button class="btn btn-sm" data-action="user-unlock" data-login="${u.login}">${icon('unlock')} Разблокировать</button>` : ''}
            ${u.login !== App.user.login ? (u.disabled ? `<button class="btn btn-sm" data-action="user-enable" data-login="${u.login}">Включить</button>` : `<button class="btn btn-sm" data-action="user-disable" data-login="${u.login}">Отключить</button>`) : '<span class="small muted">текущий сеанс</span>'}
          </div></td></tr>`;
        }).join('')}
        </tbody></table></div>
        <div class="card-body" style="border-top:1px solid var(--line)"><div class="alert alert-info">${icon('info')}<div>Пароли хранятся только в виде хэша SHA-256 с индивидуальной «солью» и не могут быть просмотрены администратором. В промышленной версии — интеграция с Active Directory / LDAP и хэширование bcrypt/Argon2 на сервере.</div></div></div></div>
        ${Object.keys(App.locks).filter((k) => !App.users.some((u) => u.login === k)).length ? `<div class="card section-gap"><div class="card-head"><h3>Попытки входа под несуществующими логинами</h3></div><div class="table-wrap"><table class="table"><thead><tr><th>Логин</th><th>Попыток</th><th>Состояние</th><th></th></tr></thead><tbody>${Object.keys(App.locks).filter((k) => !App.users.some((u) => u.login === k)).map((k) => `<tr><td class="mono">${esc(k)}</td><td>${App.locks[k].failed}</td><td>${isLocked(k) ? '<span class="badge b-bad">заблокирован</span>' : '—'}</td><td class="right"><button class="btn btn-sm" data-action="user-unlock" data-login="${esc(k)}">Сбросить</button></td></tr>`).join('')}</tbody></table></div></div>` : ''}`;
    },
  };

  /* ---------- Политика безопасности ---------- */
  PAGES.policy = {
    title: 'Политика безопасности',
    crumbs: () => 'Безопасность · параметры',
    render() {
      const p = App.policy;
      return `<div class="card" style="max-width:760px"><div class="card-head"><h3>Параметры механизмов защиты</h3></div>
        <div class="card-body"><div class="form-grid">
          <div class="field"><label>Неудачных попыток до блокировки</label><select class="input" id="p-att">${[3, 5, 10].map((n) => opt(n, n, p.maxAttempts)).join('')}</select><div class="hint">По заданию ПЗ № 5 — 5 попыток</div></div>
          <div class="field"><label>Длительность блокировки, мин</label><select class="input" id="p-lock">${[5, 15, 30, 60].map((n) => opt(n, n, p.lockMin)).join('')}</select></div>
          <div class="field"><label>Тайм-аут бездействия, мин</label><select class="input" id="p-to">${[1, 2, 5, 10, 15].map((n) => opt(n, n, p.timeoutMin)).join('')}</select><div class="hint">Для демонстрации выберите 1 минуту</div></div>
          <div class="field"><label>Время показа раскрытых ПДн, с</label><select class="input" id="p-rev">${[15, 30, 60].map((n) => opt(n, n, p.revealSec)).join('')}</select></div>
          <div class="field span-2"><label class="checkbox"><input type="checkbox" id="p-wm" ${p.watermark ? 'checked' : ''}><span>Водяной знак с логином и АРМ на всех экранах (сдерживание утечек через фото/снимки экрана)</span></label></div>
        </div></div>
        <div class="modal-foot" style="border-radius:0 0 var(--radius) var(--radius)"><button class="btn btn-primary" data-action="policy-save">${icon('check')} Применить политику</button></div></div>`;
    },
  };

  /* ---------- О прототипе ---------- */
  PAGES.about = {
    title: 'О прототипе',
    crumbs: () => 'Справка',
    render(r) {
      const tab = r.params.tab || 'info';
      const T = [['info', 'Описание'], ['roles', 'Роли и меню'], ['nav', 'Схема навигации'], ['db', 'Структура БД'], ['check', 'Чек-лист безопасности']];
      const base = App.user ? '#about' : '#about';
      const tabs = `<div class="tabs">${T.map(([k, t]) => `<a class="tab ${k === tab ? 'active' : ''}" href="${base}?tab=${k}">${t}</a>`).join('')}</div>`;
      let body = '';
      if (tab === 'info') body = aboutInfo();
      if (tab === 'roles') body = aboutRoles();
      if (tab === 'nav') body = aboutNav();
      if (tab === 'db') body = aboutDB();
      if (tab === 'check') body = aboutChecklist();
      return tabs + body;
    },
  };
  function aboutInfo() {
    return `<div class="grid grid-21">
      <div class="card card-pad">
        <h3 style="font-size:20px;color:var(--ink);margin-bottom:10px">АИС «Комнатки» — работающий макет</h3>
        <p>Прототип автоматизированной информационной системы управления гостиничным комплексом, разработанный по техническому заданию (ПЗ № 2) на стадии эскизного проекта (ГОСТ Р 59793-2021) в рамках этапа «Прототипирование» плана-графика ЖЦ (ПЗ № 4, недели 11–12, КТ-4 «Демонстрация прототипа заказчику»).</p>
        <p>Макет реализован как одностраничное веб-приложение (HTML5, CSS3, JavaScript), что соответствует требованию ТЗ к клиентской части «через веб-браузеры». Данные хранятся локально в браузере и являются <b>вымышленными</b> — реальные ПДн на стенде не используются (мера защиты этапа прототипирования из ПЗ № 4).</p>
        <h4 style="margin:18px 0 8px;color:var(--ink)">Реализованные экранные формы</h4>
        <ol class="list-plain">
          <li><b>Вход в систему</b> — логин, пароль (не отображается), блокировка после 5 неудачных попыток.</li>
          <li><b>Главное окно</b> с меню, зависящим от роли (5 вариантов меню).</li>
          <li><b>Списки объектов</b> с поиском и фильтрами: номерной фонд, гости, бронирования.</li>
          <li><b>Карточка гостя</b> с маскированием ПДн и контролируемым раскрытием.</li>
          <li><b>Отчёты / печатные формы</b> с грифом «Конфиденциально» / «ДСП».</li>
          <li><b>Журнал действий пользователей</b> — только для администратора безопасности.</li>
          <li>Дополнительно: форма бронирования с проверкой данных, лицевые счета, отзывы и жалобы, управление учётными записями, политика безопасности.</li>
        </ol>
      </div>
      <div class="card card-pad">
        <h4 style="color:var(--ink);margin-bottom:8px">Как проверить механизмы защиты</h4>
        <ol class="list-plain small">
          <li>Введите неверный пароль 5 раз — учётная запись будет заблокирована.</li>
          <li>Войдите как <span class="mono">security</span> → «Учётные записи» → разблокируйте.</li>
          <li>Войдите как <span class="mono">marketing</span> и откройте адрес <span class="mono">#guests</span> — будет отказ 403 и запись в журнале.</li>
          <li>Как <span class="mono">reception</span> откройте карточку гостя → «Показать ПДн».</li>
          <li>Создайте бронирование с неверными датами — сработает проверка.</li>
          <li>Удалите бронирование — потребуется ввести «УДАЛИТЬ».</li>
          <li>Как <span class="mono">security</span> в «Политике» поставьте тайм-аут 1 мин и не трогайте мышь.</li>
          <li>В журнале нажмите «Тест: исказить запись», затем «Проверить целостность».</li>
        </ol>
        <div class="kv section-gap"><span>Таблиц БД</span><b>7</b></div>
        <div class="kv"><span>Записей в БД</span><b>${App.db.buildings.length + App.db.rooms.length + App.db.guests.length + App.db.companies.length + App.db.bookings.length + App.db.charges.length + App.db.reviews.length}</b></div>
        <div class="kv"><span>Ролей</span><b>5</b></div>
      </div></div>`;
  }
  function aboutRoles() {
    const sym = (n, r) => n.roles.includes(r) ? '<span class="yes">●</span>' : '<span class="no">—</span>';
    const caps = [
      ['Создание и изменение бронирований', 'editBooking'], ['Регистрация и изменение гостей', 'editGuest'], ['Раскрытие полных ПДн (с указанием цели)', 'revealPD'],
      ['Начисление услуг', 'addCharge'], ['Приём оплаты', 'takePayment'], ['Регистрация отзывов, статусы жалоб', 'editReview'],
    ];
    const menuOf = (role) => NAV.filter((n) => n.roles.includes(role)).map((n) => `<li>${icon(n.icon)} ${esc(n.title)}</li>`).join('');
    return `<div class="card"><div class="card-head"><h3>Матрица доступа к разделам (RBAC)</h3></div><div class="table-wrap"><table class="table matrix"><thead><tr><th>Раздел / функция</th>${ALL.map((r) => `<th>${esc(ROLES[r].short)}</th>`).join('')}</tr></thead><tbody>
      ${NAV.map((n) => `<tr><td>${esc(n.title)}</td>${ALL.map((r) => `<td>${sym(n, r)}</td>`).join('')}</tr>`).join('')}
      ${caps.map(([t, k]) => `<tr><td class="small"><i>${esc(t)}</i></td>${ALL.map((r) => `<td>${CAN[k].includes(r) ? '<span class="yes">●</span>' : '<span class="no">—</span>'}</td>`).join('')}</tr>`).join('')}
      </tbody></table></div><div class="card-body small muted" style="border-top:1px solid var(--line)">● — доступно. Администратор безопасности не имеет доступа к ПДн гостей и финансам (разделение обязанностей), а пользователи — к журналу и настройкам защиты.</div></div>
      <div class="grid grid-2 section-gap">
        <div class="card"><div class="card-head"><h3>Меню пользователя (Администратор рецепции)</h3></div><div class="card-body"><ul class="menu-preview">${menuOf('reception')}</ul></div></div>
        <div class="card"><div class="card-head"><h3>Меню администратора безопасности</h3></div><div class="card-body"><ul class="menu-preview">${menuOf('secadmin')}</ul></div></div>
      </div>
      <style>.menu-preview{list-style:none;margin:0;padding:12px;border-radius:12px;background:var(--ink);display:grid;gap:4px}.menu-preview li{display:flex;gap:10px;align-items:center;color:#dfe5f2;font-weight:600;padding:8px 10px;border-radius:8px}.menu-preview li:first-child{background:rgba(212,169,74,.18)}.menu-preview svg{width:17px;height:17px;color:var(--gold)}</style>`;
  }
  function aboutNav() {
    const sections = [
      ['Номерной фонд', 'Рецепция, Руководство'], ['Бронирования', 'Рецепция, Касса, Руководство'], ['Гости', 'Рецепция, Касса'],
      ['Лицевые счета', 'Касса, Руководство'], ['Отзывы и жалобы', 'Маркетинг, Руководство'], ['Отчёты', 'Все, кроме АБ'],
      ['Журнал событий', 'Администратор безопасности'], ['Учётные записи', 'Администратор безопасности'], ['Политика безопасности', 'Администратор безопасности'], ['О прототипе', 'Все роли'],
    ];
    const subs = { 1: ['Форма бронирования', 'Рецепция'], 2: ['Карточка гостя (ПДн)', 'Рецепция — раскрытие'], 5: ['Печатная форма с грифом', 'по типу отчёта'] };
    const H = 62, top = 40;
    let svg = `<svg class="nav-map" viewBox="0 0 1000 ${top + sections.length * H + 20}" font-family="Manrope, sans-serif">
      <defs><marker id="ar" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path d="M0 0 10 5 0 10z" fill="#8a93a6"/></marker></defs>`;
    const midY = top + (sections.length * H) / 2 - 30;
    const box = (x, y, w, h, title, sub, fill, stroke, tc) => `<rect x="${x}" y="${y}" width="${w}" height="${h}" rx="10" fill="${fill}" stroke="${stroke}" stroke-width="1.5"/><text x="${x + 14}" y="${y + 22}" font-size="14" font-weight="700" fill="${tc}">${esc(title)}</text>${sub ? `<text x="${x + 14}" y="${y + 40}" font-size="11.5" fill="${tc}" opacity=".75">${esc(sub)}</text>` : ''}`;
    svg += box(10, midY, 150, 60, 'Вход в систему', 'все пользователи', '#14213d', '#14213d', '#fff');
    svg += `<line x1="160" y1="${midY + 30}" x2="215" y2="${midY + 30}" stroke="#8a93a6" stroke-width="1.6" marker-end="url(#ar)"/>`;
    svg += box(218, midY, 170, 60, 'Главное окно', 'меню по роли', '#d4a94a', '#c99c3c', '#14213d');
    svg += `<text x="20" y="${midY + 92}" font-size="11" fill="#c0392b">5 ошибок → блокировка</text>`;
    svg += `<text x="20" y="${midY + 108}" font-size="11" fill="#b7791f">тайм-аут → возврат ко входу</text>`;
    sections.forEach((s, i) => {
      const y = top + i * H;
      const sec = i >= 6 && i <= 8;
      svg += `<path d="M388 ${midY + 30} C 430 ${midY + 30}, 420 ${y + 24}, 462 ${y + 24}" fill="none" stroke="#b5bccb" stroke-width="1.3" marker-end="url(#ar)"/>`;
      svg += box(465, y, 240, 48, s[0], s[1], sec ? '#fbe5e2' : '#fff', sec ? '#e8a99f' : '#d8d2c6', sec ? '#8e2a1f' : '#14213d');
      if (subs[i]) {
        svg += `<line x1="705" y1="${y + 24}" x2="752" y2="${y + 24}" stroke="#8a93a6" stroke-width="1.5" marker-end="url(#ar)"/>`;
        svg += box(755, y, 230, 48, subs[i][0], subs[i][1], '#e3eefa', '#b9d2ee', '#234f80');
      }
    });
    svg += `<text x="10" y="22" font-size="12" fill="#6b7385">Прямой переход на экран, недоступный роли, → экран «403 Доступ запрещён» + запись в журнал</text></svg>`;
    return `<div class="card card-pad">${svg}</div>`;
  }
  function aboutDB() {
    const t = [
      ['Корпуса (buildings)', App.db.buildings.length, 'id (PK), название, класс (звёзды), этажей, комнат на этаже, базовый тариф'],
      ['Номера (rooms)', App.db.rooms.length, 'id (PK), корпус (FK → Корпуса), номер, этаж, категория, вместимость'],
      ['Гости (guests)', App.db.guests.length, 'id (PK), фамилия, имя, отчество, дата рождения, паспорт, телефон, e-mail, дата согласия на обработку ПДн'],
      ['Организации (companies)', App.db.companies.length, 'id (PK), название, вид деятельности, скидка %, № договора, срок действия'],
      ['Бронирования (bookings)', App.db.bookings.length, 'id (PK), гость (FK), номер (FK), организация (FK, необяз.), заезд, выезд, гостей, статус, стоимость, оплачено, примечание'],
      ['Начисления услуг (charges)', App.db.charges.length, 'id (PK), бронь (FK → Бронирования), услуга (FK → прейскурант), количество, сумма, дата'],
      ['Отзывы и жалобы (reviews)', App.db.reviews.length, 'id (PK), гость (FK), тип, тема, оценка, текст, статус, дата'],
    ];
    return `<div class="card"><div class="card-head"><h3>Логическая структура базы данных макета</h3></div><div class="table-wrap"><table class="table"><thead><tr><th>Таблица</th><th>Записей</th><th>Поля и ключи</th></tr></thead><tbody>
      ${t.map((r) => `<tr><td><b>${esc(r[0])}</b></td><td>${r[1]}</td><td class="small">${esc(r[2])}</td></tr>`).join('')}
      </tbody></table></div><div class="card-body small muted" style="border-top:1px solid var(--line)">Служебные таблицы: учётные записи (логин, ФИО, роль, соль, хэш пароля), журнал событий (с цепочкой хэшей), счётчики блокировок, политика безопасности. В промышленной версии — PostgreSQL 15+ с ролями и правами на уровне СУБД (ПЗ № 6).</div></div>`;
  }
  function aboutChecklist() {
    const rows = [
      ['Аутентификация перед доступом к данным', 'Да — экран входа; без сеанса доступен только экран входа и справка; пароли хранятся в виде хэша SHA-256 с солью; сообщение об ошибке не раскрывает существование логина', 'Серверная аутентификация через Active Directory / LDAP (ТЗ п. 4.5), хэширование Argon2/bcrypt, HTTPS (TLS 1.3), сессионные cookie HttpOnly/Secure; для администраторов — двухфакторная аутентификация'],
      ['Блокировка после неуспешных попыток входа', 'Да — после 5 неудачных попыток УЗ блокируется на 15 мин, выводится сообщение о блокировке, событие пишется в журнал; разблокировка — администратором безопасности', 'Политика блокировки на сервере/в AD, учёт попыток по логину и IP, оповещение администратора ИБ, CAPTCHA при подозрительной активности'],
      ['Меню и функции зависят от роли', 'Да — 5 ролей, меню строится по матрице RBAC; прямой переход по ссылке на чужой экран даёт ошибку 403 и запись в журнал; кнопки изменения скрыты для ролей без права', 'Проверка прав на сервере для каждого REST-запроса; роли и права в PostgreSQL (GRANT, Row Level Security) — ПЗ № 6'],
      ['Маскирование персональных данных', 'Да — паспорт ****1234, телефон, e-mail и дата рождения маскируются в списках, карточках и отчётах; раскрытие только для рецепции с указанием цели, на 30 с, с записью в журнал', 'Маскирование на стороне сервера (данные не передаются клиенту), шифрование полей ПДн в БД, политики доступа к столбцам'],
      ['Проверка корректности вводимых данных', 'Да — обязательные поля, формат даты (календарь), паспорта, телефона, e-mail; выпадающие списки вместо ручного ввода; проверка пересечения броней, вместимости, суммы оплаты; экранирование вывода (защита от XSS)', 'Повторная валидация на сервере, параметризованные запросы (защита от SQL-инъекций), ограничения CHECK/FOREIGN KEY в СУБД'],
      ['Подтверждение удаления и других опасных действий', 'Да — диалог подтверждения для отмены брони, оплаты, разблокировки, изменения политики; удаление требует ввода слова «УДАЛИТЬ»; запрет удаления записей с финансовыми операциями', 'То же + мягкое удаление (пометка), согласование критичных операций вторым сотрудником, резервное копирование перед массовыми операциями'],
      ['Журнал действий пользователей', 'Да — регистрируются входы, ошибки, блокировки, отказы в доступе, просмотр ПДн, изменения данных, печать и выгрузка; доступ только у администратора безопасности; цепочка хэшей SHA-256 и проверка целостности', 'Журнал на отдельном сервере/в SIEM, только добавление (append-only), синхронизация времени, хранение не менее 6 месяцев, резервное копирование'],
      ['Автоматическое завершение сеанса при бездействии', 'Да — тайм-аут 5 мин (настраивается), таймер в шапке, предупреждение за 30 с, затем выход с записью в журнал; сеанс завершается при закрытии вкладки', 'Тайм-аут сессии на сервере, инвалидация токена, блокировка экрана рабочей станции средствами ОС/GPO'],
    ];
    return `<div class="card"><div class="card-head"><h3>Таблица 1 — Чек-лист безопасности прототипа</h3></div><div class="table-wrap"><table class="table checklist"><thead><tr><th>№</th><th>Требование безопасности интерфейса</th><th>Реализовано в прототипе (да/нет, где)</th><th>Как будет реализовано в полной версии</th></tr></thead><tbody>
      ${rows.map((r, i) => `<tr><td>${i + 1}</td><td><b>${esc(r[0])}</b></td><td class="small"><span class="badge b-ok" style="margin-bottom:6px">Да</span><br>${esc(r[1].replace(/^Да — /, ''))}</td><td class="small">${esc(r[2])}</td></tr>`).join('')}
      </tbody></table></div></div>`;
  }

  /* ---------------- Обработка действий ---------------- */
  document.addEventListener('click', async (e) => {
    const backdrop = e.target.closest('[data-backdrop]');
    if (backdrop && e.target === backdrop && !modalOpts.noClose) { closeModal(false); return; }
    const row = e.target.closest('tr[data-href]');
    if (row && !e.target.closest('a,button')) { location.hash = row.dataset.href; return; }
    const el = e.target.closest('[data-action]');
    if (!el) return;
    const a = el.dataset.action;
    if (el.tagName === 'A') e.preventDefault();
    switch (a) {
      case 'demo-fill': $('#login').value = el.dataset.login; $('#password').value = el.dataset.pwd; $('#password').focus(); break;
      case 'reset-data': {
        const ok = await confirmDanger({ title: 'Сбросить демо-данные?', text: 'Будут восстановлены исходные тестовые данные, учётные записи, блокировки и очищен журнал событий.', confirmLabel: 'Сбросить', requireText: 'СБРОС' });
        if (!ok) return;
        Object.values(KEYS).forEach((k) => store.del(k)); store.sdel(KEYS.session);
        initState(); audit('DATA_RESET', 'Стенд', 'Успех', 'Восстановлены исходные демо-данные', { login: 'system', role: '—' });
        toast('Демо-данные восстановлены'); render(); break;
      }
      case 'logout': warnOpen = false; logout('manual'); break;
      case 'session-continue': warnOpen = false; touch(); closeModal(); break;
      case 'modal-cancel': closeModal(false); break;
      case 'modal-ok': closeModal(true); break;
      case 'toggle-nav': $('#shell').classList.toggle('nav-open'); break;
      case 'guest-new': guestForm(null); break;
      case 'guest-edit': guestForm(guestById(el.dataset.id)); break;
      case 'guest-delete': deleteGuest(el.dataset.id); break;
      case 'pd-reveal': revealPD(el.dataset.id); break;
      case 'pd-hide': revealed = null; render(); break;
      case 'booking-cancel': cancelBooking(el.dataset.id); break;
      case 'booking-delete': deleteBooking(el.dataset.id); break;
      case 'period-preset': $('#b-from').value = TODAY; $('#b-to').value = addDays(TODAY, +el.dataset.days); PAGES.bookings.redraw(); break;
      case 'period-clear': $('#b-from').value = ''; $('#b-to').value = ''; PAGES.bookings.redraw(); break;
      case 'charge-new': chargeForm(); break;
      case 'payment-new': paymentForm(); break;
      case 'review-new': reviewForm(); break;
      case 'report-apply': {
        const f = $('#rp-from').value, t = $('#rp-to').value;
        if (!isValidISO(f) || !isValidISO(t) || f > t) { toast('Укажите корректный период: дата «с» не позже даты «по»', 'bad'); return; }
        location.hash = `#reports?type=bookings&from=${f}&to=${t}`; break;
      }
      case 'report-print': {
        const rep = REPORTS.find((x) => x.id === el.dataset.type);
        App.db.seq.report++; saveDB();
        audit('REPORT_PRINT', 'Отчёт «' + rep.title + '»', 'Успех', rep.pd ? 'Гриф «Конфиденциально», экз. № 1' : 'Гриф «ДСП»');
        window.print(); break;
      }
      case 'report-csv': {
        const rep = REPORTS.find((x) => x.id === el.dataset.type);
        const p = App.route.params;
        const rows = reportRows(rep.id, p.from || addDays(TODAY, -30), p.to || addDays(TODAY, 30));
        const ok = await confirmDanger({ title: 'Выгрузка данных из системы', text: rep.pd ? 'Отчёт содержит персональные данные (в маскированном виде). Выгружаемый файл должен храниться и передаваться в соответствии с политикой обработки ПДн. Факт выгрузки будет записан в журнал.' : 'Факт выгрузки будет записан в журнал событий.', confirmLabel: 'Выгрузить', danger: false });
        if (!ok) return;
        downloadCSV(`otchet_${rep.id}_${TODAY}.csv`, [rows.head].concat(rows.body, rows.foot ? [rows.foot] : []));
        audit('EXPORT', 'Отчёт «' + rep.title + '»', 'Успех', 'Формат CSV'); toast('Файл выгружен'); break;
      }
      case 'audit-verify': showVerify(); break;
      case 'audit-export':
        downloadCSV(`audit_${TODAY}.csv`, [['№', 'Время', 'Пользователь', 'Роль', 'АРМ', 'Событие', 'Объект', 'Результат', 'Подробности', 'Хэш']].concat(App.audit.map((x) => [x.n, fmtDT(x.ts), x.login, x.role, x.ws, EVENTS[x.event] || x.event, x.object, x.result, x.details, x.hash])));
        audit('AUDIT_EXPORT', 'Журнал событий', 'Успех', `Выгружено ${App.audit.length - 1} записей`); PAGES.audit.redraw(); break;
      case 'audit-tamper': {
        const ok = await confirmDanger({ title: 'Имитация атаки на журнал', text: 'Будет изменён текст одной из записей журнала напрямую в хранилище — так, как это сделал бы злоумышленник в обход интерфейса. После этого запустите проверку целостности.', confirmLabel: 'Исказить запись' });
        if (!ok) return;
        const cand = App.audit.filter((x) => x.event === 'LOGIN_FAIL' || x.event === 'ACCESS_DENIED');
        const target = cand.length ? cand[cand.length - 1] : App.audit[Math.max(0, App.audit.length - 3)];
        target.details = 'Запись исправлена: событие отсутствовало';
        target.result = 'Успех';
        store.set(KEYS.audit, App.audit);
        toast(`Запись № ${target.n} изменена в обход интерфейса`, 'warn'); PAGES.audit.redraw(); break;
      }
      case 'user-unlock': {
        const login = el.dataset.login;
        const ok = await confirmDanger({ title: `Разблокировать «${login}»?`, text: 'Счётчик неудачных попыток будет сброшен. Убедитесь, что попытки входа выполнял сам сотрудник, а не злоумышленник.', confirmLabel: 'Разблокировать', danger: false });
        if (!ok) return;
        delete App.locks[login]; saveLocks();
        audit('USER_UNLOCK', 'УЗ ' + login, 'Успех', 'Разблокирована администратором безопасности'); toast('Учётная запись разблокирована'); render(); break;
      }
      case 'user-disable': case 'user-enable': {
        const u = App.users.find((x) => x.login === el.dataset.login);
        const dis = a === 'user-disable';
        const ok = await confirmDanger({ title: `${dis ? 'Отключить' : 'Включить'} учётную запись «${u.login}»?`, text: dis ? 'Сотрудник не сможет войти в систему до повторного включения (например, при увольнении или отпуске).' : 'Сотрудник снова сможет войти в систему.', confirmLabel: dis ? 'Отключить' : 'Включить', danger: dis });
        if (!ok) return;
        u.disabled = dis; saveUsers();
        audit(dis ? 'USER_DISABLE' : 'USER_ENABLE', 'УЗ ' + u.login, 'Успех', ROLES[u.role].name); toast('Готово'); render(); break;
      }
      case 'policy-save': {
        const np = { maxAttempts: +$('#p-att').value, lockMin: +$('#p-lock').value, timeoutMin: +$('#p-to').value, revealSec: +$('#p-rev').value, watermark: $('#p-wm').checked };
        const diff = Object.keys(np).filter((k) => np[k] !== App.policy[k]);
        if (!diff.length) { toast('Изменений нет', 'warn'); return; }
        const ok = await confirmDanger({ title: 'Изменить политику безопасности?', text: 'Новые параметры применяются ко всем пользователям немедленно. Изменение будет записано в журнал.', confirmLabel: 'Применить', danger: false });
        if (!ok) return;
        const desc = diff.map((k) => `${k}: ${App.policy[k]} → ${np[k]}`).join('; ');
        App.policy = np; store.set(KEYS.policy, np);
        audit('POLICY_CHANGE', 'Политика безопасности', 'Успех', desc); toast('Политика применена'); render(); break;
      }
      default: break;
    }
  });
  // Ошибка поля снимается, как только пользователь его исправляет
  document.addEventListener('input', (e) => { if (e.target.classList && e.target.classList.contains('invalid') && e.target.id) setErr(e.target.id, ''); });
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && $('#modal-root').innerHTML && !modalOpts.noClose) closeModal(false); });
  window.addEventListener('hashchange', () => { $('#shell') && $('#shell').classList.remove('nav-open'); render(); });
  // Синхронизация между вкладками: выход в одной вкладке завершает сеанс и в других
  window.addEventListener('storage', (e) => { if (e.key === KEYS.audit) App.audit = store.get(KEYS.audit, []); if (e.key === KEYS.locks) App.locks = store.get(KEYS.locks, {}); });

  initState();
  restoreSession();
  render();
})();
