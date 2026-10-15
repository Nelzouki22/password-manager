// Applied in <head> before first paint so the page never flashes the wrong theme.
(function () {
  var theme = "light";
  try {
    theme = localStorage.getItem("pwm-theme") ||
      (window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
  } catch (e) { /* storage unavailable: fall back to light */ }
  document.documentElement.setAttribute("data-bs-theme", theme);
})();
