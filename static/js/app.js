// SecureVault front-end behaviour. No inline scripts are used (strict CSP).
(function () {
  "use strict";

  var csrf = (document.querySelector('meta[name="csrf-token"]') || {}).content || "";
  var REVEAL_MS = 15000;      // auto-hide revealed passwords
  var CLIPBOARD_MS = 30000;   // auto-clear copied passwords
  var MASK = "••••••••";

  function api(url, options) {
    options = options || {};
    options.credentials = "same-origin";
    options.headers = Object.assign({ "X-CSRF-Token": csrf, "X-Requested-With": "fetch" }, options.headers || {});
    return fetch(url, options).then(function (res) {
      if (res.status === 401) { window.location.href = "/login"; throw new Error("expired"); }
      return res.json().then(function (data) {
        if (!res.ok) { throw new Error(data.error || "Request failed"); }
        return data;
      });
    });
  }

  // ---- Dark mode toggle ----------------------------------------------------
  var themeButton = document.getElementById("theme-toggle");
  function syncThemeIcon() {
    if (!themeButton) { return; }
    var dark = document.documentElement.getAttribute("data-bs-theme") === "dark";
    themeButton.innerHTML = dark ? '<i class="bi bi-sun"></i>' : '<i class="bi bi-moon-stars"></i>';
  }
  if (themeButton) {
    syncThemeIcon();
    themeButton.addEventListener("click", function () {
      var next = document.documentElement.getAttribute("data-bs-theme") === "dark" ? "light" : "dark";
      document.documentElement.setAttribute("data-bs-theme", next);
      try { localStorage.setItem("pwm-theme", next); } catch (e) { /* ignore */ }
      syncThemeIcon();
    });
  }

  // ---- Show / hide password inputs ------------------------------------------
  document.querySelectorAll("[data-toggle-password]").forEach(function (button) {
    button.addEventListener("click", function () {
      var input = document.getElementById(button.getAttribute("data-toggle-password"));
      if (!input) { return; }
      var show = input.type === "password";
      input.type = show ? "text" : "password";
      button.innerHTML = show ? '<i class="bi bi-eye-slash"></i>' : '<i class="bi bi-eye"></i>';
    });
  });

  // ---- Confirm destructive forms ---------------------------------------------
  document.querySelectorAll("form[data-confirm]").forEach(function (form) {
    form.addEventListener("submit", function (event) {
      if (!window.confirm(form.getAttribute("data-confirm"))) { event.preventDefault(); }
    });
  });

  // ---- Vault: reveal / copy ---------------------------------------------------
  var revealTimers = {};
  function fetchPassword(id) {
    return api("/credentials/" + encodeURIComponent(id) + "/reveal", { method: "POST" })
      .then(function (data) { return data.password; });
  }
  function hide(id) {
    var cell = document.getElementById("pw-" + id);
    if (cell) { cell.textContent = MASK; }
    clearTimeout(revealTimers[id]);
  }

  document.querySelectorAll('[data-action="reveal"]').forEach(function (button) {
    button.addEventListener("click", function () {
      var id = button.getAttribute("data-id");
      var cell = document.getElementById("pw-" + id);
      if (!cell) { return; }
      if (cell.textContent !== MASK) { hide(id); return; }
      fetchPassword(id).then(function (password) {
        cell.textContent = password;               // textContent: never parsed as HTML
        revealTimers[id] = setTimeout(function () { hide(id); }, REVEAL_MS);
      }).catch(function () { /* session errors redirect; others are ignored */ });
    });
  });

  document.querySelectorAll('[data-action="copy"]').forEach(function (button) {
    button.addEventListener("click", function () {
      var id = button.getAttribute("data-id");
      var original = button.innerHTML;
      fetchPassword(id).then(function (password) {
        return navigator.clipboard.writeText(password).then(function () {
          button.innerHTML = '<i class="bi bi-check2"></i>';
          setTimeout(function () { button.innerHTML = original; }, 1500);
          setTimeout(function () {
            navigator.clipboard.writeText("").catch(function () { /* ignore */ });
          }, CLIPBOARD_MS);
        });
      }).catch(function () {
        button.innerHTML = '<i class="bi bi-x-lg"></i>';
        setTimeout(function () { button.innerHTML = original; }, 1500);
      });
    });
  });

  // ---- Add/edit form: strength meter + generator -------------------------------
  var passwordInput = document.getElementById("password");
  var meter = document.getElementById("strength-meter");
  var label = document.getElementById("strength-label");
  var feedback = document.getElementById("strength-feedback");
  var timer = null;

  function renderStrength(result) {
    if (!meter) { return; }
    meter.value = result.score + 1;
    label.textContent = result.label + " (~" + result.entropy_bits + " bits)";
    feedback.textContent = "";
    result.feedback.forEach(function (tip) {
      var li = document.createElement("li");
      li.textContent = tip;
      feedback.appendChild(li);
    });
  }
  function updateStrength() {
    if (!meter || !passwordInput) { return; }
    if (!passwordInput.value) { meter.value = 0; label.textContent = " "; feedback.textContent = ""; return; }
    api("/api/strength", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: passwordInput.value })
    }).then(renderStrength).catch(function () { /* ignore */ });
  }
  if (passwordInput && meter) {
    passwordInput.addEventListener("input", function () {
      clearTimeout(timer);
      timer = setTimeout(updateStrength, 250);
    });
  }

  var generator = document.getElementById("generator");
  if (generator && passwordInput) {
    var lengthInput = document.getElementById("gen-length");
    var lengthValue = document.getElementById("gen-length-value");
    var errorBox = document.getElementById("gen-error");
    lengthInput.addEventListener("input", function () { lengthValue.textContent = lengthInput.value; });

    function flag(id) { return document.getElementById(id).checked ? "1" : "0"; }
    document.getElementById("gen-button").addEventListener("click", function () {
      var params = new URLSearchParams({
        length: lengthInput.value,
        upper: flag("gen-upper"), lower: flag("gen-lower"),
        digits: flag("gen-digits"), symbols: flag("gen-symbols"),
        ambiguous: flag("gen-ambiguous")
      });
      errorBox.textContent = "";
      api("/api/generate?" + params.toString()).then(function (data) {
        passwordInput.value = data.password;
        passwordInput.type = "text";               // let the user see what was generated
        renderStrength(data.strength);
      }).catch(function (err) { errorBox.textContent = err.message; });
    });
  }
})();
