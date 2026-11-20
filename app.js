/* Шифратор: Telegram Mini App без бэкенда, ключи статические (keys.js).
 * Шифрование: libsodium crypto_box_seal (X25519 + XSalsa20-Poly1305),
 * совместимо с PyNaCl SealedBox и tools/crypt.py.
 * После шифрования текст расшифровывается закрытым ключом и сравнивается
 * с исходным; при несовпадении результат не выдаётся.
 */
(async function () {
  "use strict";

  const tg = window.Telegram && window.Telegram.WebApp;
  const inTelegram = !!(tg && tg.initData);
  const sodium = window.sodium;
  await sodium.ready;

  const B64 = sodium.base64_variants.ORIGINAL;
  const $ = (id) => document.getElementById(id);
  const toB64 = (bytes) => sodium.to_base64(bytes, B64);
  const fromB64 = (s) => sodium.from_base64(String(s).replace(/\s+/g, ""), B64);

  if (inTelegram) {
    document.documentElement.classList.add("tg");
    tg.ready();
    tg.expand();
  }
  const haptic = (kind) => {
    try { if (inTelegram && tg.HapticFeedback) tg.HapticFeedback.notificationOccurred(kind); } catch (_) {}
  };

  let toastTimer;
  function toast(msg, kind) {
    const el = $("toast");
    el.textContent = msg;
    el.classList.add("show");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => el.classList.remove("show"), 2200);
    if (kind) haptic(kind);
  }

  // ---------- Ключи ----------
  function fail(msg) {
    $("key-error").textContent = msg;
    $("key-error").hidden = false;
    $("go").disabled = true;
    $("in").disabled = true;
  }

  const K = window.KEYS || {};
  let pk, sk = null;
  try {
    pk = fromB64(K.publicKey || "");
    if (pk.length !== sodium.crypto_box_PUBLICKEYBYTES) throw 0;
  } catch (_) {
    return fail("В keys.js неверный publicKey: нужен base64 от 32 байт.");
  }
  $("pk-short").textContent = toB64(pk).slice(0, 12) + "…";

  if (K.privateKey) {
    try {
      sk = fromB64(K.privateKey);
      if (sk.length !== sodium.crypto_box_SECRETKEYBYTES) throw 0;
    } catch (_) {
      return fail("В keys.js неверный privateKey: нужен base64 от 32 байт.");
    }
    if (!sodium.memcmp(sodium.crypto_scalarmult_base(sk), pk)) {
      return fail("Ключи в keys.js не из одной пары: privateKey не соответствует publicKey.");
    }
  }

  // ---------- Шифрование и проверка ----------
  function setCheck(state, text) {
    const el = $("check");
    el.className = "check-line " + state;
    el.textContent = text;
  }

  $("go").onclick = () => {
    const text = $("in").value;
    if (!text) return toast("Введите текст", "error");

    const ct = sodium.crypto_box_seal(sodium.from_string(text), pk);
    const b64 = toB64(ct);

    if (sk) {
      // Проверяем ровно то, что отдадим пользователю: строку base64
      let ok = false;
      try {
        const back = sodium.to_string(sodium.crypto_box_seal_open(fromB64(b64), pk, sk));
        ok = back === text;
      } catch (_) {}
      if (!ok) {
        $("out").value = "";
        $("result").hidden = false;
        $("copy").disabled = $("share").disabled = true;
        setCheck("bad", "✗ Проверка не пройдена: расшифрованный текст не совпадает с исходным");
        return haptic("error");
      }
      setCheck("good", "✓ Проверено: расшифровано и совпадает с исходным");
    } else {
      setCheck("muted", "Проверка отключена: в keys.js нет privateKey");
    }

    $("out").value = b64;
    $("result").hidden = false;
    $("copy").disabled = $("share").disabled = false;
    $("share").hidden = !inTelegram;
    haptic("success");
  };

  // Если текст поменяли, старый результат больше к нему не относится
  $("in").addEventListener("input", () => { $("result").hidden = true; });

  $("copy").onclick = async () => {
    const out = $("out");
    try {
      await navigator.clipboard.writeText(out.value);
      return toast("Скопировано", "success");
    } catch (_) {}
    out.focus();
    out.select();
    try { if (document.execCommand("copy")) return toast("Скопировано", "success"); } catch (_) {}
    toast("Не получилось, скопируйте вручную", "error");
  };

  $("share").onclick = () => {
    tg.openTelegramLink("https://t.me/share/url?url=" + encodeURIComponent($("out").value));
  };
})().catch((e) => {
  document.body.textContent = "Ошибка запуска: " + (e && e.message ? e.message : e);
});
