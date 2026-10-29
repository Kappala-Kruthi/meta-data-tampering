/**
 * Digital Forensics Application Frontend Logic
 * Implements tag filtering, comparison tab switching, hash clipboard copying,
 * and drag-and-drop file preview handlers.
 */

document.addEventListener("DOMContentLoaded", () => {
  initDropzones();
  initTableSearch();
  initComparisonTabs();
  initCopyButtons();
  initKeyboardShortcuts();
});

// Global keyboard shortcuts (d, s, c, v, h, n, ?)
function initKeyboardShortcuts() {
  document.addEventListener("keydown", (e) => {
    // Ignore shortcut execution if focus is in an input, textarea, select, or contenteditable
    const targetTag = e.target.tagName ? e.target.tagName.toLowerCase() : "";
    if (
      targetTag === "input" ||
      targetTag === "textarea" ||
      targetTag === "select" ||
      e.target.isContentEditable ||
      e.ctrlKey ||
      e.metaKey ||
      e.altKey
    ) {
      return;
    }

    const key = e.key.toLowerCase();
    switch (key) {
      case "?":
        window.location.href = "/shortcuts";
        break;
      case "d":
        window.location.href = "/dashboard";
        break;
      case "s":
        window.location.href = "/single-analysis";
        break;
      case "c":
        window.location.href = "/compare";
        break;
      case "v":
        window.location.href = "/verify";
        break;
      case "h":
        window.location.href = "/history";
        break;
      case "n":
        window.location.href = "/notifications";
        break;
      default:
        break;
    }
  });
}

// Drag and drop file upload initialization
function initDropzones() {
  const dropzones = document.querySelectorAll(".dropzone");

  dropzones.forEach((zone) => {
    const input = zone.querySelector("input[type='file']");
    const preview = zone.querySelector(".file-preview");

    if (!input) return;

    // Change event
    input.addEventListener("change", () => {
      if (input.files && input.files.length > 0) {
        showFilePreview(input.files[0], preview, zone);
      }
    });

    // Drag events
    ["dragenter", "dragover"].forEach((eventName) => {
      zone.addEventListener(eventName, (e) => {
        e.preventDefault();
        zone.classList.add("dragover");
      });
    });

    ["dragleave", "drop"].forEach((eventName) => {
      zone.addEventListener(eventName, (e) => {
        e.preventDefault();
        zone.classList.remove("dragover");
      });
    });

    zone.addEventListener("drop", (e) => {
      if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
        input.files = e.dataTransfer.files;
        showFilePreview(input.files[0], preview, zone);
        input.dispatchEvent(new Event("change", { bubbles: true }));
      }
    });
  });
}

function showFilePreview(file, previewEl, zone) {
  if (!previewEl) return;
  const sizeMB = (file.size / (1024 * 1024)).toFixed(2);
  previewEl.textContent = "Selected: " + file.name + " (" + sizeMB + " MB)";
  previewEl.style.display = "block";
  zone.style.borderColor = "var(--blue-primary)";
}

// Live table search filtering
function initTableSearch() {
  const searchInputs = document.querySelectorAll(".search-input");

  searchInputs.forEach((input) => {
    const targetTableId = input.dataset.targetTable;
    const table = document.getElementById(targetTableId);
    if (!table) return;

    input.addEventListener("input", (e) => {
      const term = e.target.value.toLowerCase().trim();
      const rows = table.querySelectorAll("tbody tr");

      rows.forEach((row) => {
        const text = row.textContent.toLowerCase();
        if (text.includes(term)) {
          row.style.display = "";
        } else {
          row.style.display = "none";
        }
      });
    });
  });
}

// Comparison differential category tabs
function initComparisonTabs() {
  const tabBtns = document.querySelectorAll(".tab-btn");
  if (!tabBtns.length) return;

  tabBtns.forEach((btn) => {
    btn.addEventListener("click", () => {
      const targetCategory = btn.dataset.category;

      // Update button active state
      tabBtns.forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");

      // Filter rows
      const compTable = document.getElementById("comparison-table");
      if (!compTable) return;

      const rows = compTable.querySelectorAll("tbody tr");
      rows.forEach((row) => {
        const cat = row.dataset.category;
        if (targetCategory === "all" || cat === targetCategory) {
          row.style.display = "";
        } else {
          row.style.display = "none";
        }
      });
    });
  });
}

// Copy hash to clipboard helper
function initCopyButtons() {
  const copyButtons = document.querySelectorAll(".btn-copy");

  copyButtons.forEach((btn) => {
    btn.addEventListener("click", () => {
      const textToCopy = btn.dataset.copyText;
      if (!textToCopy) return;

      navigator.clipboard.writeText(textToCopy).then(() => {
        const origText = btn.innerHTML;
        btn.innerHTML = "Copied";
        btn.classList.add("btn-primary");
        setTimeout(() => {
          btn.innerHTML = origText;
          btn.classList.remove("btn-primary");
        }, 2000);
      });
    });
  });
}

// Toggle Raw JSON viewer
function toggleJsonView(containerId) {
  const el = document.getElementById(containerId);
  if (!el) return;
  if (el.style.display === "none" || !el.style.display) {
    el.style.display = "block";
  } else {
    el.style.display = "none";
  }
}

// Download JSON helper
function downloadJson(dataObj, filename) {
  const jsonStr = JSON.stringify(dataObj, null, 2);
  const blob = new Blob([jsonStr], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename || "forensic_metadata.json";
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
