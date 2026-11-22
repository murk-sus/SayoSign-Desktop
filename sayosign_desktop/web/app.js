import { inspectIPA } from "./lens/inspect.js";

// ---------- i18n ----------
const S = {
  en: {
    navSign: "Sign", navCerts: "Certificates", navDevice: "Device", donate: "Support",
    signTitle: "Sign & install", signSub: "Drop an IPA, pick a certificate and your iPhone. That's it.",
    dropIpa: "Drop an .ipa here", dropIpaHint: "or click to choose · nothing leaves this computer",
    certificate: "Certificate", device: "iPhone", appName: "Name", bundleId: "Bundle ID", version: "Version",
    compression: "Compression", zNone: "None (fastest)", zFast: "Fast", zBalanced: "Balanced", zSmall: "Smallest",
    tweaks: "Tweaks", addTweak: "+ Add .deb or .dylib", removePlugins: "Remove app extensions",
    removeWatch: "Remove Apple Watch app", fileSharing: "Enable Files app sharing",
    signInstall: "Sign & install", signOnly: "Sign only",
    certsTitle: "Certificates", certsSub: "Your .p12 + .mobileprovision pairs, checked live against Apple.",
    addCert: "Add a certificate", pickP12: "Choose .p12", pickProv: "Choose .mobileprovision",
    password: "Password", nickname: "Nickname (optional)", add: "Add certificate",
    pwHint: "Leave the password empty to try common ones (1, 123, 1234…).",
    deviceTitle: "Device", deviceSub: "Apps you installed on your iPhone.", installedApps: "Installed apps",
    search: "Search apps", noDevice: "No iPhone found. Plug it in with a cable, unlock it and tap Trust.",
    noCert: "No certificates yet — add one in Certificates", noIpa: "Drop an IPA first",
    pickDevice: "No iPhone connected", decrypted: "Decrypted", encrypted: "Encrypted",
    encryptedNote: "This IPA is still App Store encrypted and will crash. Use a decrypted IPA.",
    tweaked: "Tweaked", minOS: "Min iOS", size: "Size", uploading: "Preparing…",
    stepSign: "Signing", stepInstall: "Installing on iPhone", stepDone: "Done",
    download: "Download signed IPA", installedOk: "Installed! Find it on your Home Screen.", signedOk: "Signed!",
    good: "Valid", revoked: "Revoked", unknown: "Not checked", check: "Check", remove: "Delete",
    team: "Team", expires: "Expires", type: "Profile", devices: "Devices", appId: "App ID",
    allDevices: "all", thisDevice: "Your iPhone is in this profile", notThisDevice: "Your iPhone is NOT in this profile",
    added: "Certificate added", removeConfirm: "Delete this certificate?", uninstall: "Delete",
    uninstallConfirm: "Delete {name} from your iPhone?", deleted: "Deleted", daysLeft: "{n} days left", expired: "expired",
    cliMissing: "The signing engine was not found. Run `make` in the SayoSign folder.",
    navAnisette: "Anisette", themeSystem: "Auto", themeLight: "Light", themeBlack: "Black", change: "change",
    anisetteTitle: "Anisette", anisetteSub: "Apple ID sign-in needs anisette. Since October 2026 Apple only accepts Mac-based servers.",
    aniQuick: "Quick setup", aniQuickHint: "Tests the public Mac servers right now, provisions this PC and picks the fastest one that Apple accepts.",
    aniAutoBtn: "Set up automatically", aniServer: "Server", aniOwn: "Your own server", aniUse: "Use", aniCheck: "Check", aniReset: "Reset identity",
    aniData: "Server data", aniLocal: "Anisette server on this PC", aniLocalHint: "Your iPhone uses this computer as its anisette server. Scan the QR code with the iPhone camera, it opens SayoSign and sets the server. Keep the phone on the same Wi-Fi.",
    aniProtocol: "Protocol", aniClient: "Client info", aniUA: "User agent", aniDevice: "Device ID", aniMachine: "Machine ID", aniOk: "Working", aniFail: "Not working",
    aniMac: "Mac-based, Apple accepts it", aniLegacy: "Legacy client, Apple rejects it", aniNonMac: "Not Mac-based, Apple may reject it",
    aniAddresses: "Addresses", aniUpstream: "Upstream", aniRequests: "Requests served", aniChecking: "Checking…", aniResetDone: "Anisette identity reset",
    aniSaved: "Server saved", aniPicked: "Picked {name} ({ms} ms)", aniNone: "No public server works right now. Try again later or use your own Mac server.", aniCurrent: "current",
    orWord: "or", appleidSignin: "🍎 Sign in with Apple ID", appleidTitle: "Sign in with Apple ID",
    appleidHint: "Use a free or paid developer account. A certificate and profile are created for you. Needs an anisette server.",
    anisette: "Anisette server", appleid2fa: "Apple sent a code to your trusted devices. Enter it below.", code: "Code",
    continue: "Continue", appleidDone: "Signed in 🎀", appleidKind: "Apple ID",
    deviceNotInProfile: "Warning: this iPhone is not in the certificate's profile, the app will not open.",
  },
  ru: {
    navSign: "Подпись", navCerts: "Сертификаты", navDevice: "Устройство", donate: "Поддержать",
    signTitle: "Подписать и установить", signSub: "Перетащи IPA, выбери сертификат и айфон. Всё.",
    dropIpa: "Перетащи .ipa сюда", dropIpaHint: "или нажми, чтобы выбрать · файлы не покидают компьютер",
    certificate: "Сертификат", device: "iPhone", appName: "Название", bundleId: "Bundle ID", version: "Версия",
    compression: "Сжатие", zNone: "Без сжатия (быстрее)", zFast: "Быстрое", zBalanced: "Среднее", zSmall: "Максимальное",
    tweaks: "Твики", addTweak: "+ Добавить .deb или .dylib", removePlugins: "Удалить расширения",
    removeWatch: "Удалить приложение для Watch", fileSharing: "Доступ через «Файлы»",
    signInstall: "Подписать и установить", signOnly: "Только подписать",
    certsTitle: "Сертификаты", certsSub: "Пары .p12 + .mobileprovision с живой проверкой отзыва у Apple.",
    addCert: "Добавить сертификат", pickP12: "Выбрать .p12", pickProv: "Выбрать .mobileprovision",
    password: "Пароль", nickname: "Название (необязательно)", add: "Добавить",
    pwHint: "Оставь пароль пустым — попробую популярные (1, 123, 1234…).",
    deviceTitle: "Устройство", deviceSub: "Приложения, которые ты установил на айфон.", installedApps: "Установленные приложения",
    search: "Поиск", noDevice: "Айфон не найден. Подключи кабелем, разблокируй и нажми «Доверять».",
    noCert: "Сертификатов нет — добавь во вкладке «Сертификаты»", noIpa: "Сначала перетащи IPA",
    pickDevice: "Айфон не подключён", decrypted: "Расшифрован", encrypted: "Зашифрован",
    encryptedNote: "Этот IPA всё ещё зашифрован App Store и будет вылетать. Нужен расшифрованный.",
    tweaked: "С твиками", minOS: "Мин. iOS", size: "Размер", uploading: "Готовлю…",
    stepSign: "Подпись", stepInstall: "Установка на айфон", stepDone: "Готово",
    download: "Скачать подписанный IPA", installedOk: "Установлено! Ищи на экране «Домой».", signedOk: "Подписано!",
    good: "Живой", revoked: "Отозван", unknown: "Не проверен", check: "Проверить", remove: "Удалить",
    team: "Команда", expires: "Истекает", type: "Профиль", devices: "Устройства", appId: "App ID",
    allDevices: "все", thisDevice: "Твой айфон есть в профиле", notThisDevice: "Твоего айфона НЕТ в профиле",
    added: "Сертификат добавлен", removeConfirm: "Удалить этот сертификат?", uninstall: "Удалить",
    uninstallConfirm: "Удалить {name} с айфона?", deleted: "Удалено", daysLeft: "осталось {n} дн.", expired: "истёк",
    cliMissing: "Движок подписи не найден. Выполни `make` в папке SayoSign.",
    navAnisette: "Anisette", themeSystem: "Авто", themeLight: "Светлая", themeBlack: "Чёрная", change: "изменить",
    anisetteTitle: "Anisette", anisetteSub: "Для входа через Apple ID нужен anisette. С октября 2026 Apple принимает только серверы на Mac.",
    aniQuick: "Быстрая настройка", aniQuickHint: "Прямо сейчас проверяет публичные Mac-серверы, активирует этот ПК и выбирает самый быстрый из тех, что принимает Apple.",
    aniAutoBtn: "Настроить автоматически", aniServer: "Сервер", aniOwn: "Свой сервер", aniUse: "Использовать", aniCheck: "Проверить", aniReset: "Сбросить идентичность",
    aniData: "Данные сервера", aniLocal: "Anisette-сервер на этом ПК", aniLocalHint: "Айфон будет использовать этот компьютер как anisette-сервер. Отсканируй QR камерой айфона — откроется SayoSign и сервер установится сам. Телефон должен быть в той же Wi-Fi сети.",
    aniProtocol: "Протокол", aniClient: "Client info", aniUA: "User agent", aniDevice: "ID устройства", aniMachine: "ID машины", aniOk: "Работает", aniFail: "Не работает",
    aniMac: "Mac-сервер, Apple принимает", aniLegacy: "Устаревший клиент, Apple отклоняет", aniNonMac: "Не Mac, Apple может отклонить",
    aniAddresses: "Адреса", aniUpstream: "Источник", aniRequests: "Обслужено запросов", aniChecking: "Проверяю…", aniResetDone: "Идентичность anisette сброшена",
    aniSaved: "Сервер сохранён", aniPicked: "Выбран {name} ({ms} мс)", aniNone: "Сейчас не работает ни один публичный сервер. Попробуй позже или укажи свой Mac-сервер.", aniCurrent: "текущий",
    orWord: "или", appleidSignin: "🍎 Войти через Apple ID", appleidTitle: "Вход через Apple ID",
    appleidHint: "Бесплатный или платный аккаунт разработчика. Сертификат и профиль создаются автоматически. Нужен anisette-сервер.",
    anisette: "Anisette-сервер", appleid2fa: "Apple отправил код на доверенные устройства. Введи его ниже.", code: "Код",
    continue: "Продолжить", appleidDone: "Вход выполнен 🎀", appleidKind: "Apple ID",
    deviceNotInProfile: "Внимание: этого айфона нет в профиле сертификата, приложение не откроется.",
  },
  zh: {
    navSign: "签名", navCerts: "证书", navDevice: "设备", donate: "支持作者",
    signTitle: "签名并安装", signSub: "拖入 IPA，选择证书和 iPhone，就这么简单。",
    dropIpa: "将 .ipa 拖到这里", dropIpaHint: "或点击选择 · 文件不会离开这台电脑",
    certificate: "证书", device: "iPhone", appName: "名称", bundleId: "Bundle ID", version: "版本",
    compression: "压缩", zNone: "无（最快）", zFast: "快速", zBalanced: "均衡", zSmall: "最小",
    tweaks: "插件", addTweak: "+ 添加 .deb 或 .dylib", removePlugins: "移除应用扩展",
    removeWatch: "移除 Apple Watch 应用", fileSharing: "启用“文件”共享",
    signInstall: "签名并安装", signOnly: "仅签名",
    certsTitle: "证书", certsSub: "你的 .p12 + .mobileprovision，实时向 Apple 检查吊销状态。",
    addCert: "添加证书", pickP12: "选择 .p12", pickProv: "选择 .mobileprovision",
    password: "密码", nickname: "备注（可选）", add: "添加证书",
    pwHint: "密码留空将自动尝试常用密码（1、123、1234…）。",
    deviceTitle: "设备", deviceSub: "你在 iPhone 上安装的应用。", installedApps: "已安装应用",
    search: "搜索应用", noDevice: "未找到 iPhone。请用数据线连接、解锁并点击“信任”。",
    noCert: "还没有证书 — 请在“证书”中添加", noIpa: "请先拖入 IPA",
    pickDevice: "未连接 iPhone", decrypted: "已解密", encrypted: "已加密",
    encryptedNote: "此 IPA 仍带有 App Store 加密，安装后会闪退。请使用已解密的 IPA。",
    tweaked: "已注入插件", minOS: "最低 iOS", size: "大小", uploading: "准备中…",
    stepSign: "签名", stepInstall: "安装到 iPhone", stepDone: "完成",
    download: "下载已签名 IPA", installedOk: "安装完成！在主屏幕上找到它。", signedOk: "签名完成！",
    good: "有效", revoked: "已吊销", unknown: "未检查", check: "检查", remove: "删除",
    team: "团队", expires: "到期", type: "描述文件", devices: "设备", appId: "App ID",
    allDevices: "全部", thisDevice: "你的 iPhone 在此描述文件中", notThisDevice: "你的 iPhone 不在此描述文件中",
    added: "证书已添加", removeConfirm: "删除此证书？", uninstall: "删除",
    uninstallConfirm: "从 iPhone 删除 {name}？", deleted: "已删除", daysLeft: "剩余 {n} 天", expired: "已过期",
    cliMissing: "未找到签名引擎。请在 SayoSign 目录中运行 `make`。",
    navAnisette: "Anisette", themeSystem: "自动", themeLight: "浅色", themeBlack: "黑色", change: "更改",
    anisetteTitle: "Anisette", anisetteSub: "Apple ID 登录需要 Anisette。自 2026 年 10 月起，Apple 只接受基于 Mac 的服务器。",
    aniQuick: "快速设置", aniQuickHint: "立即测试公共 Mac 服务器，为这台电脑配置，并选择 Apple 接受的最快服务器。",
    aniAutoBtn: "自动设置", aniServer: "服务器", aniOwn: "你自己的服务器", aniUse: "使用", aniCheck: "检查", aniReset: "重置身份",
    aniData: "服务器数据", aniLocal: "本机 Anisette 服务器", aniLocalHint: "iPhone 将把这台电脑用作 Anisette 服务器。用 iPhone 相机扫描二维码，会打开 SayoSign 并自动设置服务器。手机需连接同一 Wi-Fi。",
    aniProtocol: "协议", aniClient: "Client info", aniUA: "User agent", aniDevice: "设备 ID", aniMachine: "机器 ID", aniOk: "正常", aniFail: "不可用",
    aniMac: "基于 Mac，Apple 接受", aniLegacy: "旧版客户端，Apple 会拒绝", aniNonMac: "非 Mac，Apple 可能拒绝",
    aniAddresses: "地址", aniUpstream: "上游", aniRequests: "已处理请求", aniChecking: "检查中…", aniResetDone: "Anisette 身份已重置",
    aniSaved: "服务器已保存", aniPicked: "已选择 {name}（{ms} 毫秒）", aniNone: "目前没有可用的公共服务器。请稍后再试或使用你自己的 Mac 服务器。", aniCurrent: "当前",
    orWord: "或", appleidSignin: "🍎 使用 Apple ID 登录", appleidTitle: "使用 Apple ID 登录",
    appleidHint: "使用免费或付费开发者账号，自动创建证书和描述文件。需要 anisette 服务器。",
    anisette: "Anisette 服务器", appleid2fa: "Apple 已向你的受信任设备发送验证码，请在下方输入。", code: "验证码",
    continue: "继续", appleidDone: "已登录 🎀", appleidKind: "Apple ID",
    deviceNotInProfile: "注意：此 iPhone 不在证书的描述文件中，应用将无法打开。",
  },
};
let lang = (() => { try { return localStorage.getItem("lang"); } catch { return null; } })() || (navigator.language || "en").slice(0, 2);
if (!S[lang]) lang = "en";
const t = (k, v = {}) => (S[lang][k] || S.en[k] || k).replace(/\{(\w+)\}/g, (_, x) => v[x]);
function applyLang() {
  document.documentElement.lang = lang;
  document.querySelectorAll("[data-t]").forEach((el) => (el.textContent = t(el.dataset.t)));
  document.querySelectorAll("[data-tp]").forEach((el) => (el.placeholder = t(el.dataset.tp)));
  document.querySelectorAll("[data-lang]").forEach((b) => b.classList.toggle("on", b.dataset.lang === lang));
}

// ---------- api ----------
const token = new URLSearchParams(location.hash.slice(1)).get("token") || sessionStorage.getItem("token") || "";
sessionStorage.setItem("token", token);
history.replaceState(null, "", "/");
async function api(path, opts = {}) {
  const r = await fetch(path, { ...opts, headers: { "X-Token": token, ...(opts.body && !(opts.body instanceof Blob) ? { "Content-Type": "application/json" } : {}), ...(opts.headers || {}) } });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || r.statusText);
  return data;
}
function upload(file, onProgress) {
  return new Promise((ok, fail) => {
    const x = new XMLHttpRequest();
    x.open("POST", "/api/files");
    x.setRequestHeader("X-Token", token);
    x.setRequestHeader("X-Filename", encodeURIComponent(file.name).replace(/%20/g, " "));
    x.upload.onprogress = (e) => e.lengthComputable && onProgress && onProgress(e.loaded / e.total);
    x.onload = () => (x.status === 200 ? ok(JSON.parse(x.responseText)) : fail(new Error(x.responseText)));
    x.onerror = () => fail(new Error("upload failed"));
    x.send(file);
  });
}

// ---------- helpers ----------
const $ = (s) => document.querySelector(s);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const fmtSize = (n) => { const u = ["B", "KB", "MB", "GB"]; let i = 0; while (n >= 1024 && i < 3) { n /= 1024; i++; } return `${n.toFixed(i ? 1 : 0)} ${u[i]}`; };
const days = (iso) => Math.floor((new Date(iso) - Date.now()) / 86400000);
const fmtDate = (iso) => new Date(iso).toLocaleDateString(lang === "zh" ? "zh-CN" : lang, { year: "numeric", month: "short", day: "numeric" });
function toast(msg) {
  const el = $("#toast");
  el.textContent = msg;
  el.hidden = false;
  clearTimeout(toast.t);
  toast.t = setTimeout(() => (el.hidden = true), 2600);
}
function pickFile(input) {
  return new Promise((ok) => {
    input.onchange = () => { ok([...input.files]); input.value = ""; };
    input.click();
  });
}

// ---------- state ----------
const st = { ipa: null, ipaFile: null, ipaUpload: null, tweaks: [], certs: [], devices: [], p12: null, prov: null };

// ---------- navigation ----------
document.querySelectorAll(".nav").forEach((b) => b.addEventListener("click", () => {
  document.querySelectorAll(".nav").forEach((x) => x.classList.toggle("on", x === b));
  document.querySelectorAll(".view").forEach((v) => v.classList.toggle("on", v.id === "view-" + b.dataset.view));
  if (b.dataset.view === "device") loadApps();
  if (b.dataset.view === "anisette") loadAnisette();
}));
document.querySelectorAll("[data-lang]").forEach((b) => b.addEventListener("click", () => {
  lang = b.dataset.lang;
  try { localStorage.setItem("lang", lang); } catch {}
  applyLang(); renderIpa(); renderCerts(); renderDevices();
}));

// ---------- IPA ----------
const drop = $("#ipa-drop");
drop.addEventListener("click", async () => { const [f] = await pickFile($("#ipa-input")); if (f) setIpa(f); });
drop.addEventListener("keydown", (e) => { if (e.key === "Enter") drop.click(); });
document.addEventListener("dragover", (e) => { e.preventDefault(); drop.classList.add("over"); });
document.addEventListener("dragleave", (e) => { if (!e.relatedTarget) drop.classList.remove("over"); });
document.addEventListener("drop", (e) => {
  e.preventDefault();
  drop.classList.remove("over");
  const files = [...(e.dataTransfer?.files || [])];
  const ipa = files.find((f) => /\.t?ipa$/i.test(f.name));
  if (ipa) setIpa(ipa);
  const tw = files.filter((f) => /\.(deb|dylib)$/i.test(f.name));
  if (tw.length) addTweaks(tw);
});

async function setIpa(file) {
  st.ipaFile = file;
  st.ipa = null;
  st.ipaUpload = null;
  st.uploadPct = 0;
  renderIpa();
  try { st.ipa = await inspectIPA(file); } catch (e) { st.ipa = { error: e.message }; }
  if (st.ipa && !st.ipa.error) {
    $("#opt-name").placeholder = st.ipa.name || "";
    $("#opt-bundle").placeholder = st.ipa.bundleId || "";
    $("#opt-version").placeholder = st.ipa.version || "";
  }
  renderIpa();
  st.ipaUpload = upload(file, (p) => { st.uploadPct = p; const bar = $("#upbar"); if (bar) bar.style.width = p * 100 + "%"; });
  st.ipaUpload.then(() => { const b = $("#upbar"); if (b) b.parentElement.hidden = true; }).catch(() => {});
}

function renderIpa() {
  const card = $("#ipa-card");
  drop.classList.toggle("small", !!st.ipaFile);
  if (!st.ipaFile) { card.hidden = true; return; }
  card.hidden = false;
  const r = st.ipa;
  if (!r) { card.innerHTML = `<div class="app-head"><div class="ph">⏳</div><div><h2>${esc(st.ipaFile.name)}</h2></div></div>`; return; }
  if (r.error) { card.innerHTML = `<h2>${esc(st.ipaFile.name)}</h2><p class="note bad">${esc(r.error)}</p>`; return; }
  const icon = r.icon ? URL.createObjectURL(new Blob([r.icon], { type: "image/png" })) : "";
  card.innerHTML = `
    <div class="app-head">
      ${icon ? `<img src="${icon}" alt="">` : `<div class="ph"><svg class="i" viewBox="0 0 24 24"><path d="M3.5 7.5l8.5-4 8.5 4v9l-8.5 4-8.5-4z"/><path d="M3.5 7.5l8.5 4 8.5-4M12 11.5V20"/></svg></div>`}
      <div>
        <h2>${esc(r.name)}</h2>
        <div class="mono muted">${esc(r.bundleId)}</div>
        <div class="badges">
          ${r.encrypted ? `<span class="badge bad">${t("encrypted")}</span>` : `<span class="badge good">${t("decrypted")}</span>`}
          ${r.tweaked ? `<span class="badge warn">${t("tweaked")}</span>` : ""}
        </div>
      </div>
    </div>
    ${r.encrypted ? `<p class="note bad">${t("encryptedNote")}</p>` : ""}
    <div class="facts">
      <div class="fact"><span>${t("version")}</span><b>${esc(r.version)}</b></div>
      <div class="fact"><span>${t("minOS")}</span><b>${esc(r.minOS || "—")}</b></div>
      <div class="fact"><span>${t("size")}</span><b>${fmtSize(r.fileSize)}</b></div>
    </div>
    <div class="upbar" ${st.uploadPct >= 1 ? "hidden" : ""}><i id="upbar" style="width:${(st.uploadPct || 0) * 100}%"></i></div>`;
}

// ---------- tweaks ----------
$("#tweak-add").addEventListener("click", async () => addTweaks(await pickFile($("#tweak-input"))));
function addTweaks(files) {
  for (const f of files) {
    const tw = { name: f.name, upload: upload(f) };
    st.tweaks.push(tw);
  }
  renderTweaks();
}
function renderTweaks() {
  $("#tweak-list").innerHTML = st.tweaks.map((tw, i) => `<span class="chip">${esc(tw.name)}<button data-i="${i}" title="remove">×</button></span>`).join("");
}
$("#tweak-list").addEventListener("click", (e) => {
  const b = e.target.closest("button[data-i]");
  if (b) { st.tweaks.splice(Number(b.dataset.i), 1); renderTweaks(); }
});

// ---------- certificates ----------
async function loadCerts() {
  try { st.certs = await api("/api/certs"); } catch { st.certs = []; }
  try { st.accounts = await api("/api/appleid"); } catch { st.accounts = []; }
  renderCerts();
}
function certStatus(c) {
  const s = c.ocsp?.status;
  if (s === "GOOD") return `<span class="badge good">● ${t("good")}</span>`;
  if (s === "REVOKED") return `<span class="badge bad">● ${t("revoked")}</span>`;
  return `<span class="badge">● ${t("unknown")}</span>`;
}
function expiryBadge(iso) {
  const n = days(iso);
  return `${esc(fmtDate(iso))} <span class="badge ${n < 0 ? "bad" : n < 14 ? "warn" : "good"}">${n < 0 ? t("expired") : t("daysLeft", { n })}</span>`;
}
function renderCerts() {
  const sel = $("#cert-select");
  const prev = sel.value;
  const accounts = st.accounts || [];
  const certOpts = st.certs.filter((c) => !c.error).map((c) => `<option value="${c.id}">${c.ocsp?.status === "REVOKED" ? "⛔ " : c.ocsp?.status === "GOOD" ? "🟢 " : ""}${esc(c.nickname || c.team || c.name)} · ${esc(c.profile?.type || "")}</option>`).join("");
  const aidOpts = accounts.map((a) => `<option value="${a.id}">🍎 ${esc(a.email)} · ${esc(a.team)}</option>`).join("");
  sel.innerHTML = (certOpts || aidOpts) ? certOpts + aidOpts : `<option value="">${t("noCert")}</option>`;
  if ([...sel.options].some((o) => o.value === prev)) sel.value = prev;
  renderAccounts(accounts);

  const udids = st.devices.map((d) => d.udid.toUpperCase());
  $("#cert-list").innerHTML = st.certs.map((c) => {
    if (c.error) return `<div class="card cert"><p class="note bad">${esc(c.error)}</p><button class="danger" data-del="${c.id}">${t("remove")}</button></div>`;
    const devs = c.profile.devices.map((d) => d.toUpperCase());
    const inProfile = c.profile.allDevices || udids.some((u) => devs.includes(u));
    return `<div class="card cert">
      <div class="row-inline between"><h3>${esc(c.nickname || c.team)}</h3>${certStatus(c)}</div>
      <div class="muted small">${esc(c.name)}</div>
      <dl class="kv">
        <dt>${t("team")}</dt><dd>${esc(c.team)} <span class="mono muted">${esc(c.teamId)}</span></dd>
        <dt>${t("expires")}</dt><dd>${expiryBadge(c.expires)}</dd>
        <dt>${t("type")}</dt><dd>${esc(c.profile.type)} · ${t("expires").toLowerCase()} ${esc(fmtDate(c.profile.expires))}</dd>
        <dt>${t("appId")}</dt><dd class="mono">${esc(c.profile.appId)}</dd>
        <dt>${t("devices")}</dt><dd>${c.profile.allDevices ? t("allDevices") : c.profile.devices.length}</dd>
      </dl>
      ${udids.length ? `<p class="note ${inProfile ? "good" : "bad"}">${inProfile ? t("thisDevice") : t("notThisDevice")}</p>` : ""}
      <div class="row-inline" style="margin-top:12px">
        <button class="secondary" data-check="${c.id}">${t("check")}</button>
        <button class="danger" data-del="${c.id}">${t("remove")}</button>
      </div>
    </div>`;
  }).join("");
}
$("#cert-list").addEventListener("click", async (e) => {
  const chk = e.target.closest("[data-check]");
  const del = e.target.closest("[data-del]");
  if (chk) {
    chk.disabled = true;
    try {
      const info = await api(`/api/certs/${chk.dataset.check}/check`, { method: "POST" });
      st.certs = st.certs.map((c) => (c.id === info.id ? info : c));
      renderCerts();
    } catch (err) { toast(err.message); chk.disabled = false; }
  }
  if (del && confirm(t("removeConfirm"))) {
    await api(`/api/certs/${del.dataset.del}`, { method: "DELETE" });
    loadCerts();
  }
});
$("#pick-p12").addEventListener("click", async () => {
  const [f] = await pickFile($("#p12-input"));
  if (f) { st.p12 = f; $("#pick-p12 .fp-name").textContent = f.name; $("#pick-p12").classList.add("set"); }
});
$("#pick-prov").addEventListener("click", async () => {
  const [f] = await pickFile($("#prov-input"));
  if (f) { st.prov = f; $("#pick-prov .fp-name").textContent = f.name; $("#pick-prov").classList.add("set"); }
});
$("#cert-save").addEventListener("click", async () => {
  const msg = $("#cert-msg");
  msg.className = "msg";
  msg.textContent = "";
  if (!st.p12 || !st.prov) { msg.className = "msg bad note"; msg.textContent = `${t("pickP12")} + ${t("pickProv")}`; return; }
  const btn = $("#cert-save");
  btn.disabled = true;
  try {
    const [a, b] = await Promise.all([upload(st.p12), upload(st.prov)]);
    await api("/api/certs", { method: "POST", body: JSON.stringify({ p12: a.id, profile: b.id, password: $("#cert-pw").value, nickname: $("#cert-nick").value }) });
    toast(t("added"));
    st.p12 = st.prov = null;
    $("#cert-pw").value = $("#cert-nick").value = "";
    $("#pick-p12 .fp-name").textContent = t("pickP12");
    $("#pick-prov .fp-name").textContent = t("pickProv");
    document.querySelectorAll(".filepick").forEach((x) => x.classList.remove("set"));
    loadCerts();
  } catch (err) {
    msg.className = "msg bad note";
    msg.textContent = err.message;
  }
  btn.disabled = false;
});

// ---------- Apple ID ----------
function renderAccounts(accounts) {
  const host = $("#cert-list");
  const extra = accounts.map((a) => `<div class="card cert">
      <div class="row-inline between"><h3>🍎 ${esc(a.email)}</h3><span class="badge good">Apple ID</span></div>
      <dl class="kv">
        <dt>${t("team")}</dt><dd>${esc(a.team)} <span class="mono muted">${esc(a.teamId)}</span></dd>
        <dt>${t("expires")}</dt><dd>${expiryBadge(a.expires)}</dd>
      </dl>
      <div class="row-inline" style="margin-top:12px"><button class="danger" data-aiddel="${a.id}">${t("remove")}</button></div>
    </div>`).join("");
  host.insertAdjacentHTML("afterbegin", extra);
}
let aidState = null;
$("#appleid-btn").addEventListener("click", (e) => {
  e.preventDefault();
  aidState = null;
  $("#appleid-step1").hidden = false; $("#appleid-step2").hidden = true;
  $("#aid-msg").textContent = ""; $("#aid-submit").textContent = t("continue");
  api("/api/anisette").then((a) => ($("#aid-server").textContent = a.server)).catch(() => {});
  $("#appleid-dialog").showModal();
});
$("#appleid-form").addEventListener("submit", async (e) => {
  if (e.submitter && e.submitter.value === "cancel") return;
  e.preventDefault();
  const msg = $("#aid-msg"); msg.className = "msg"; msg.textContent = "…";
  const submit = $("#aid-submit"); submit.disabled = true;
  try {
    if (!aidState) {
      const r = await api("/api/appleid/login", { method: "POST", body: JSON.stringify({
        email: $("#aid-email").value.trim(), password: $("#aid-pass").value, }) });
      if (r.needs2FA) { aidState = r.id; $("#appleid-step1").hidden = true; $("#appleid-step2").hidden = false; msg.textContent = ""; $("#aid-code").focus(); }
      else { done(); }
    } else {
      await api("/api/appleid/2fa", { method: "POST", body: JSON.stringify({ id: aidState, code: $("#aid-code").value.trim() }) });
      done();
    }
  } catch (err) { msg.className = "msg bad note"; msg.textContent = err.message; }
  submit.disabled = false;
  function done() { $("#appleid-dialog").close(); toast(t("appleidDone")); loadCerts(); }
});
$("#cert-list").addEventListener("click", async (e) => {
  const d = e.target.closest("[data-aiddel]");
  if (d && confirm(t("removeConfirm"))) { await api(`/api/appleid/${d.dataset.aiddel}`, { method: "DELETE" }); loadCerts(); }
});

// ---------- devices ----------
async function loadDevices() {
  try { st.devices = (await api("/api/devices")).filter((d) => d.udid); } catch { st.devices = []; }
  renderDevices();
  renderCerts();
}
function renderDevices() {
  const sel = $("#device-select");
  const prev = sel.value;
  sel.innerHTML = st.devices.length
    ? st.devices.map((d) => `<option value="${esc(d.udid)}">${esc(d.name || d.udid)} · iOS ${esc(d.ios || "?")} · ${esc(d.connection)}</option>`).join("")
    : `<option value="">${t("pickDevice")}</option>`;
  if ([...sel.options].some((o) => o.value === prev)) sel.value = prev;
  $("#device-info").innerHTML = st.devices.length
    ? st.devices.map((d) => `<div class="card dev-card"><div class="dev-ico"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><rect x="7" y="2.5" width="10" height="19" rx="2.5"/><line x1="11" y1="18.5" x2="13" y2="18.5"/></svg></div><div><h3 style="margin:0">${esc(d.name || "iPhone")}</h3>
        <div class="muted">${esc(d.model || "")} · iOS ${esc(d.ios || "?")} (${esc(d.build || "")}) · ${esc(d.connection)}</div>
        <div class="mono muted small">${esc(d.udid)}</div>${d.error ? `<p class="note bad">${esc(d.error)}</p>` : ""}</div></div>`).join("")
    : `<div class="card empty">${t("noDevice")}</div>`;
}
$("#device-refresh").addEventListener("click", loadDevices);

let apps = [];
async function loadApps() {
  await loadDevices();
  const udid = st.devices[0]?.udid;
  if (!udid) { apps = []; renderApps(); return; }
  try { apps = await api(`/api/devices/${encodeURIComponent(udid)}/apps`); } catch (e) { apps = []; toast(e.message); }
  renderApps();
}
function renderApps() {
  const q = $("#apps-search").value.toLowerCase();
  const list = apps.filter((a) => !q || a.name.toLowerCase().includes(q) || a.bundleId.toLowerCase().includes(q));
  $("#apps-list").innerHTML = list.length ? list.map((a) => `<div class="app-row"><div><b>${esc(a.name)}</b><span class="mono muted small">${esc(a.bundleId)} · ${esc(a.version || "")}</span></div>
    <button class="danger" data-un="${esc(a.bundleId)}" data-name="${esc(a.name)}">${t("uninstall")}</button></div>`).join("") : `<div class="empty">—</div>`;
}
$("#apps-search").addEventListener("input", renderApps);
$("#apps-refresh").addEventListener("click", loadApps);
$("#apps-list").addEventListener("click", async (e) => {
  const b = e.target.closest("[data-un]");
  if (!b || !confirm(t("uninstallConfirm", { name: b.dataset.name }))) return;
  b.disabled = true;
  try {
    await api(`/api/devices/${encodeURIComponent(st.devices[0].udid)}/apps/${encodeURIComponent(b.dataset.un)}`, { method: "DELETE" });
    toast(t("deleted"));
    loadApps();
  } catch (err) { toast(err.message); b.disabled = false; }
});

// ---------- signing ----------
$("#go-install").addEventListener("click", () => start(true));
$("#go-sign").addEventListener("click", () => start(false));

async function start(install) {
  if (!st.ipaFile) return toast(t("noIpa"));
  const cert = $("#cert-select").value;
  if (!cert) return toast(t("noCert"));
  const udid = $("#device-select").value;
  if (install && !udid) return toast(t("noDevice"));
  const c = st.certs.find((x) => x.id === cert);
  if (install && c && !c.profile.allDevices && !c.profile.devices.map((d) => d.toUpperCase()).includes(udid.toUpperCase())) {
    if (!confirm(t("deviceNotInProfile"))) return;
  }
  const buttons = [$("#go-install"), $("#go-sign")];
  buttons.forEach((b) => (b.disabled = true));
  const job = $("#job");
  job.hidden = false;
  const steps = install ? ["stepSign", "stepInstall"] : ["stepSign"];
  job.innerHTML = `<div class="steps">${steps.map((s, i) => `<div class="step" id="st-${i}"><div class="dot">${i + 1}</div><b>${t(s)}</b><span class="muted small" id="pc-${i}"></span><div class="bar"><i id="bar-${i}"></i></div></div>`).join("")}</div><div class="result" id="job-result"></div>`;
  const setStep = (i, cls, pct, label) => {
    const el = $(`#st-${i}`);
    if (!el) return;
    el.className = "step " + cls;
    if (pct != null) { $(`#bar-${i}`).style.width = pct + "%"; $(`#pc-${i}`).textContent = (label ? label + " · " : "") + Math.round(pct) + "%"; }
    if (cls === "ok") el.querySelector(".dot").textContent = "✓";
    if (cls === "fail") el.querySelector(".dot").textContent = "!";
  };
  setStep(0, "active", 0, t("uploading"));
  try {
    const ipa = await st.ipaUpload;
    const tweaks = await Promise.all(st.tweaks.map((x) => x.upload));
    const z = $("#opt-z").value;
    const { id } = await api("/api/jobs", {
      method: "POST",
      body: JSON.stringify({
        ipa: ipa.id, cert, udid: install ? udid : null,
        options: {
          name: $("#opt-name").value.trim(), bundleId: $("#opt-bundle").value.trim(), version: $("#opt-version").value.trim(),
          tweaks: tweaks.map((x) => x.id), removePlugins: $("#opt-x").checked, removeWatch: $("#opt-w").checked,
          fileSharing: $("#opt-f").checked, compression: z === "" ? null : Number(z),
        },
      }),
    });
    await new Promise((resolve) => {
      const es = new EventSource(`/api/jobs/${id}/events?token=${encodeURIComponent(token)}`);
      es.onmessage = (m) => {
        const ev = JSON.parse(m.data);
        if (ev.stage === "sign") setStep(0, "active", ev.percent, ev.step);
        if (ev.stage === "signed") {
          setStep(0, "ok", 100);
          if (install) setStep(1, "active", 0);
          $("#job-result").innerHTML = `<a class="secondary" href="${ev.download}?token=${encodeURIComponent(token)}">⬇ ${t("download")} (${fmtSize(ev.size)})</a>`;
          if (!install) $("#job-result").insertAdjacentHTML("afterbegin", `<b>🎀 ${t("signedOk")}</b>`);
        }
        if (ev.stage === "install") setStep(1, "active", ev.percent);
        if (ev.stage === "installed") { setStep(1, "ok", 100); $("#job-result").insertAdjacentHTML("afterbegin", `<b>🎀 ${t("installedOk")}</b>`); }
        if (ev.stage === "error") {
          const i = document.querySelector(".step.active") ? Number(document.querySelector(".step.active").id.slice(3)) : 0;
          setStep(i, "fail");
          $("#job-result").innerHTML = `<p class="note bad">${esc(ev.error)}</p>`;
        }
        if (ev.stage === "done" || ev.stage === "error") { es.close(); resolve(); }
      };
      es.onerror = () => { es.close(); resolve(); };
    });
  } catch (err) {
    setStep(0, "fail");
    $("#job-result").innerHTML = `<p class="note bad">${esc(err.message)}</p>`;
  }
  buttons.forEach((b) => (b.disabled = false));
}

// ---------- boot ----------
// ---------- theme ----------
function applyTheme(mode) {
  if (mode === "light" || mode === "black") document.documentElement.dataset.theme = mode;
  else delete document.documentElement.dataset.theme;
  document.querySelectorAll("[data-theme-set]").forEach((b) => b.classList.toggle("on", b.dataset.themeSet === (mode || "system")));
}
let themeMode = (() => { try { return localStorage.getItem("theme") || "system"; } catch { return "system"; } })();
document.querySelectorAll("[data-theme-set]").forEach((b) => b.addEventListener("click", () => {
  themeMode = b.dataset.themeSet;
  try { localStorage.setItem("theme", themeMode); } catch {}
  applyTheme(themeMode);
}));
applyTheme(themeMode);

// ---------- anisette ----------
let ani = null;
async function loadAnisette() {
  try { ani = await api("/api/anisette"); } catch (e) { toast(e.message); return; }
  $("#ani-presets").innerHTML = ani.presets.map((p) => `<button class="preset ${p.url === ani.server ? "on" : ""}" data-url="${esc(p.url)}"><b>${esc(p.name)}</b><span class="mono small">${esc(p.url.replace("https://", ""))}</span></button>`).join("");
  if (!ani.presets.some((p) => p.url === ani.server)) $("#ani-url").value = ani.server;
  $("#aid-server") && ($("#aid-server").textContent = ani.server);
  renderRelay(ani.relay);
  checkAnisette();
}
function aniRow(k, v) { return `<dt>${esc(k)}</dt><dd>${v}</dd>`; }
async function checkAnisette() {
  $("#ani-state").className = "badge"; $("#ani-state").textContent = t("aniChecking");
  $("#ani-info").innerHTML = "";
  let st;
  try { st = await api("/api/anisette/check", { method: "POST", body: JSON.stringify({}) }); } catch (e) { st = { ok: false, error: e.message }; }
  $("#ani-state").className = "badge " + (st.ok ? "good" : "bad");
  $("#ani-state").textContent = st.ok ? t("aniOk") : t("aniFail");
  const kind = st.mac ? `<span class="badge good">${t("aniMac")}</span>` : st.legacy ? `<span class="badge bad">${t("aniLegacy")}</span>` : st.ok ? `<span class="badge warn">${t("aniNonMac")}</span>` : "";
  $("#ani-info").innerHTML = st.ok ? [
    aniRow(t("aniServer"), `<span class="mono">${esc(st.server)}</span>`),
    aniRow(t("aniProtocol"), `${esc(st.version)} ${kind}`),
    aniRow(t("aniClient"), `<span class="mono small">${esc(st.clientInfo)}</span>`),
    aniRow(t("aniUA"), `<span class="mono small">${esc(st.userAgent)}</span>`),
    aniRow(t("aniDevice"), `<span class="mono small">${esc(st.deviceId)}</span>`),
    aniRow(t("aniMachine"), `<span class="mono small">${esc(st.machineId)}</span>`),
  ].join("") : aniRow(t("aniServer"), `<span class="mono">${esc(st.server || "")}</span>`) + `<dt></dt><dd class="note bad">${esc(st.error || "")}</dd>`;
}
function renderRelay(r) {
  $("#ani-relay").checked = !!r.running;
  $("#ani-relay-box").innerHTML = r.running ? `
    <div class="relay">
      <div class="qr">${r.qr || ""}</div>
      <dl class="kv">
        ${aniRow(t("aniAddresses"), r.addresses.map((a) => `<span class="mono">${esc(a)}</span>`).join("<br>"))}
        ${aniRow(t("aniUpstream"), `<span class="mono small">${esc(r.upstream)}</span>`)}
        ${aniRow(t("aniRequests"), String(r.requests))}
      </dl>
    </div>` : "";
}
$("#ani-presets").addEventListener("click", async (e) => {
  const b = e.target.closest("[data-url]"); if (!b) return;
  await api("/api/anisette", { method: "POST", body: JSON.stringify({ server: b.dataset.url }) });
  toast(t("aniSaved")); loadAnisette();
});
$("#ani-save").addEventListener("click", async () => {
  try { await api("/api/anisette", { method: "POST", body: JSON.stringify({ server: $("#ani-url").value }) }); toast(t("aniSaved")); loadAnisette(); }
  catch (e) { toast(e.message); }
});
$("#ani-check").addEventListener("click", checkAnisette);
$("#ani-reset").addEventListener("click", async () => { await api("/api/anisette/reset", { method: "POST" }); toast(t("aniResetDone")); checkAnisette(); });
$("#ani-auto").addEventListener("click", async () => {
  const btn = $("#ani-auto"); btn.disabled = true;
  $("#ani-auto-res").innerHTML = `<p class="muted small">${t("aniChecking")}</p>`;
  try {
    const r = await api("/api/anisette/auto", { method: "POST" });
    $("#ani-auto-res").innerHTML = r.results.map((x) => `<div class="res"><span class="dot ${x.ok && x.mac ? "ok" : "bad"}"></span><b>${esc(x.name)}</b><span class="muted small">${x.ok ? x.ms + " ms" : esc((x.error || "").slice(0, 60))}</span></div>`).join("") +
      `<p class="note ${r.best ? "good" : "bad"}">${r.best ? t("aniPicked", { name: r.best.name, ms: r.best.ms }) : t("aniNone")}</p>`;
    loadAnisette();
  } catch (e) { $("#ani-auto-res").innerHTML = `<p class="note bad">${esc(e.message)}</p>`; }
  btn.disabled = false;
});
$("#ani-relay").addEventListener("change", async (e) => {
  try { renderRelay(await api("/api/anisette/relay", { method: "POST", body: JSON.stringify({ on: e.target.checked }) })); }
  catch (err) { toast(err.message); e.target.checked = false; }
});
document.addEventListener("click", (e) => {
  if (e.target.id === "aid-change") { e.preventDefault(); $("#appleid-dialog").close(); document.querySelector('.nav[data-view="anisette"]').click(); }
});

applyLang();
renderIpa();
(async () => {
  const s = await api("/api/status").catch(() => ({}));
  if (s.cli === false) toast(t("cliMissing"));
  await Promise.all([loadCerts(), loadDevices()]);
})();
setInterval(() => { if (!document.hidden) loadDevices(); }, 8000);
