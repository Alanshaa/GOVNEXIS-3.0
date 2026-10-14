/**
 * GOVNEXIS 3.0 | NEXION — Interactive Client Application Script
 * Theme: Light Mode by default for first-time visitors, with persistent Dark Mode toggle.
 * Pure SVG icons — No emojis.
 */

document.addEventListener("DOMContentLoaded", () => {
  initTheme();
  initAccordions();
  initTabs();
  initCopyButtons();
  initMobileSidebar();
  initScanRunner();
});

/* --------------------------------------------------------------------------
   CSRF Helper
   -------------------------------------------------------------------------- */
function getCsrfToken() {
  const meta = document.querySelector('meta[name="csrf-token"]');
  return meta ? meta.getAttribute("content") : "";
}

/* --------------------------------------------------------------------------
   Theme Switcher (Default: Light Mode)
   -------------------------------------------------------------------------- */
const SUN_SVG = `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line></svg>`;

const MOON_SVG = `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>`;

function initTheme() {
  // First-time visitors get "light" by default
  const savedTheme = localStorage.getItem("govnexis-theme") || "light";
  document.documentElement.setAttribute("data-theme", savedTheme);

  const toggleBtn = document.getElementById("theme-toggle-btn");
  if (toggleBtn) {
    updateThemeBtn(toggleBtn, savedTheme);
    toggleBtn.addEventListener("click", () => {
      const current = document.documentElement.getAttribute("data-theme") || "light";
      const next = current === "light" ? "dark" : "light";
      document.documentElement.setAttribute("data-theme", next);
      localStorage.setItem("govnexis-theme", next);
      updateThemeBtn(toggleBtn, next);

      // Notify any active charts to adjust their color palette
      window.dispatchEvent(new CustomEvent("themechange", { detail: { theme: next } }));
    });
  }
}

function updateThemeBtn(btn, theme) {
  if (theme === "dark") {
    btn.innerHTML = `${SUN_SVG}<span>Light Mode</span>`;
    btn.setAttribute("aria-label", "Switch to Light Mode");
  } else {
    btn.innerHTML = `${MOON_SVG}<span>Dark Mode</span>`;
    btn.setAttribute("aria-label", "Switch to Dark Mode");
  }
}

/* --------------------------------------------------------------------------
   Accordions
   -------------------------------------------------------------------------- */
function initAccordions() {
  document.querySelectorAll(".finding-header").forEach(header => {
    header.addEventListener("click", () => {
      const body = header.nextElementSibling;
      if (body && body.classList.contains("finding-body")) {
        const isOpen = body.classList.contains("open");
        body.classList.toggle("open", !isOpen);
        const icon = header.querySelector(".accordion-icon");
        if (icon) {
          icon.style.transform = isOpen ? "rotate(0deg)" : "rotate(90deg)";
        }
      }
    });
  });
}

/* --------------------------------------------------------------------------
   Tabs Navigation
   -------------------------------------------------------------------------- */
function initTabs() {
  document.querySelectorAll(".tabs-nav").forEach(nav => {
    const buttons = nav.querySelectorAll(".tab-btn");
    buttons.forEach(btn => {
      btn.addEventListener("click", () => {
        const targetId = btn.getAttribute("data-tab");
        if (!targetId) return;

        buttons.forEach(b => b.classList.remove("active"));
        btn.classList.add("active");

        const container = nav.parentElement;
        container.querySelectorAll(".tab-content").forEach(pane => {
          pane.classList.remove("active");
        });
        const targetPane = document.getElementById(targetId);
        if (targetPane) targetPane.classList.add("active");
      });
    });
  });
}

/* --------------------------------------------------------------------------
   Copy to Clipboard
   -------------------------------------------------------------------------- */
function initCopyButtons() {
  document.querySelectorAll(".btn-copy").forEach(btn => {
    btn.addEventListener("click", () => {
      const text = btn.getAttribute("data-copy");
      if (text) {
        navigator.clipboard.writeText(text).then(() => {
          const original = btn.textContent;
          btn.textContent = "Copied";
          setTimeout(() => { btn.textContent = original; }, 1500);
        });
      }
    });
  });
}

/* --------------------------------------------------------------------------
   Mobile Sidebar Toggle
   -------------------------------------------------------------------------- */
function initMobileSidebar() {
  const toggle = document.getElementById("mobile-sidebar-toggle");
  const sidebar = document.querySelector(".app-sidebar");
  if (toggle && sidebar) {
    toggle.addEventListener("click", () => {
      sidebar.classList.toggle("open");
    });
  }
}

/* --------------------------------------------------------------------------
   Scan Execution Runner with Progressive Visual States
   -------------------------------------------------------------------------- */
function initScanRunner() {
  const scanForm = document.getElementById("scan-form");
  const progressBox = document.getElementById("scan-progress-box");
  const progressBar = document.getElementById("scan-progress-bar");
  const progressPhase = document.getElementById("scan-progress-phase");
  const scanSubmitBtn = document.getElementById("scan-submit-btn");

  if (!scanForm || !progressBox) return;

  scanForm.addEventListener("submit", () => {
    progressBox.style.display = "block";
    scanSubmitBtn.disabled = true;
    scanSubmitBtn.innerHTML = `<span class="pulse-dot"></span> Auditing Target...`;

    let percent = 15;
    progressBar.style.width = percent + "%";
    progressPhase.textContent = "Phase 1/5: Validating target syntax and network boundaries...";

    const interval = setInterval(() => {
      if (percent < 90) {
        percent += 15;
        progressBar.style.width = percent + "%";
        if (percent >= 35 && percent < 60) {
          progressPhase.textContent = "Phase 2/5: DNS safety checks and SSRF perimeter verification...";
        } else if (percent >= 60 && percent < 80) {
          progressPhase.textContent = "Phase 3/5: Probing HTTP response headers and TLS ciphers...";
        } else if (percent >= 80) {
          progressPhase.textContent = "Phase 4/5: Evaluating rules against CISA BOD 18-01 and CVSS v3.0...";
        }
      }
    }, 400);
  });
}

/* --------------------------------------------------------------------------
   Quick URL Fill Helpers
   -------------------------------------------------------------------------- */
function fillTargetUrl(url) {
  const input = document.getElementById("target_url");
  const checkbox = document.getElementById("auth_confirmed");
  if (input) input.value = url;
  if (checkbox) checkbox.checked = true;
}

/* --------------------------------------------------------------------------
   Chart.js Dashboard Visualizations (Theme-Aware)
   -------------------------------------------------------------------------- */
let globalCharts = [];
let cachedTrendsData = null;

window.addEventListener("themechange", () => {
  if (cachedTrendsData) {
    renderDashboardCharts(cachedTrendsData);
  }
});

function getChartColors(theme) {
  const isDark = theme === "dark";
  return {
    textColor: isDark ? "#A5A5B5" : "#666675",
    gridColor: isDark ? "#2C2C39" : "#EBEBF2",
    surfaceBorder: isDark ? "#242430" : "#FFFFFF",
  };
}

function renderDashboardCharts(trendsData) {
  if (!trendsData || typeof Chart === "undefined") return;
  cachedTrendsData = trendsData;

  // Clear existing instances if re-rendering on theme switch
  globalCharts.forEach(c => c.destroy());
  globalCharts = [];

  const currentTheme = document.documentElement.getAttribute("data-theme") || "light";
  const colors = getChartColors(currentTheme);

  // 1. Official CVSS v3.0 Severity Distribution Doughnut Chart
  const cvssCanvas = document.getElementById("chart-cvss-distribution");
  if (cvssCanvas) {
    const cvssDist = trendsData.cvss_severity_counts || {};
    const chart1 = new Chart(cvssCanvas, {
      type: "doughnut",
      data: {
        labels: ["Critical", "High", "Medium", "Low", "None", "Not Scored"],
        datasets: [{
          data: [
            cvssDist["Critical"] || 0,
            cvssDist["High"] || 0,
            cvssDist["Medium"] || 0,
            cvssDist["Low"] || 0,
            cvssDist["None"] || 0,
            cvssDist["Not Scored"] || 0,
          ],
          backgroundColor: [
            "#DC2626", // Critical Red
            "#EA580C", // High Orange
            "#D97706", // Medium Amber
            "#2563EB", // Low Blue
            "#059669", // None Green
            "#64748B", // Not Scored Slate
          ],
          borderColor: colors.surfaceBorder,
          borderWidth: 2,
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: "bottom",
            labels: { color: colors.textColor, font: { size: 11, family: "Inter" } }
          }
        },
        cutout: "68%"
      }
    });
    globalCharts.push(chart1);
  }

  // 2. Activity / Score Trend Line Chart
  const trendCanvas = document.getElementById("chart-activity-trend");
  if (trendCanvas) {
    const activity = trendsData.activity_over_time || [];
    const labels = activity.map(a => a.date);
    const scores = activity.map(a => a.avg_score);
    const counts = activity.map(a => a.count);

    const chart2 = new Chart(trendCanvas, {
      type: "line",
      data: {
        labels: labels.length ? labels : ["No data"],
        datasets: [
          {
            label: "Avg Compliance Score",
            data: scores.length ? scores : [0],
            borderColor: "#8B5CF6", // Brand Purple
            backgroundColor: "rgba(139, 92, 246, 0.08)",
            fill: true,
            tension: 0.25,
            yAxisID: "yScore",
            borderWidth: 2,
          },
          {
            label: "Scans Audited",
            data: counts.length ? counts : [0],
            borderColor: "#A5A5B5",
            backgroundColor: "transparent",
            borderDash: [4, 4],
            yAxisID: "yCount",
            borderWidth: 1.5,
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        interaction: { mode: "index", intersect: false },
        scales: {
          x: {
            ticks: { color: colors.textColor, font: { size: 10 } },
            grid: { color: colors.gridColor }
          },
          yScore: {
            type: "linear",
            position: "left",
            min: 0,
            max: 100,
            ticks: { color: "#8B5CF6", font: { size: 10 } },
            grid: { color: colors.gridColor }
          },
          yCount: {
            type: "linear",
            position: "right",
            min: 0,
            ticks: { color: colors.textColor, font: { size: 10 } },
            grid: { drawOnChartArea: false }
          }
        },
        plugins: {
          legend: {
            position: "top",
            labels: { color: colors.textColor, font: { size: 11, family: "Inter" } }
          }
        }
      }
    });
    globalCharts.push(chart2);
  }

  // 3. Finding Categories Bar Chart
  const catCanvas = document.getElementById("chart-categories");
  if (catCanvas) {
    const catMap = trendsData.category_counts || {};
    const catLabels = Object.keys(catMap);
    const catValues = Object.values(catMap);

    const chart3 = new Chart(catCanvas, {
      type: "bar",
      data: {
        labels: catLabels.length ? catLabels : ["No findings"],
        datasets: [{
          label: "Findings Identified",
          data: catValues.length ? catValues : [0],
          backgroundColor: "rgba(139, 92, 246, 0.65)",
          borderColor: "#7C3AED",
          borderWidth: 1,
          borderRadius: 4
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        indexAxis: "y",
        scales: {
          x: {
            ticks: { color: colors.textColor, font: { size: 10 } },
            grid: { color: colors.gridColor }
          },
          y: {
            ticks: { color: colors.textColor, font: { size: 10 } },
            grid: { display: false }
          }
        },
        plugins: {
          legend: { display: false }
        }
      }
    });
    globalCharts.push(chart3);
  }
}
