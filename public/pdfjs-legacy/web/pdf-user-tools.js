(function () {
  "use strict";

  const params = new URLSearchParams(window.location.search);
  const rawFile = params.get("file") || "";
  const documentKey = params.get("doc") || rawFile.replace(/([?&]token=)[^&]+/g, "$1redacted");
  const storageKey = `ya-pdf-reader-tools:v1:${documentKey}`;

  const state = {
    notes: [],
    bookmarks: [],
  };

  const escapeHtml = (value) =>
    String(value || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");

  const load = () => {
    try {
      const saved = JSON.parse(localStorage.getItem(storageKey) || "{}");
      state.notes = Array.isArray(saved.notes) ? saved.notes : [];
      state.bookmarks = Array.isArray(saved.bookmarks) ? saved.bookmarks : [];
    } catch (_) {
      state.notes = [];
      state.bookmarks = [];
    }
  };

  const save = () => {
    localStorage.setItem(
      storageKey,
      JSON.stringify({
        notes: state.notes,
        bookmarks: state.bookmarks,
      })
    );
  };

  const currentPage = () => {
    const app = window.PDFViewerApplication;
    const pageFromViewer = Number(app && app.pdfViewer && app.pdfViewer.currentPageNumber);
    if (Number.isFinite(pageFromViewer) && pageFromViewer > 0) return pageFromViewer;
    const pageFromInput = Number(document.getElementById("pageNumber")?.value);
    return Number.isFinite(pageFromInput) && pageFromInput > 0 ? pageFromInput : 1;
  };

  const goToPage = (page) => {
    const app = window.PDFViewerApplication;
    if (app && app.pdfViewer) {
      app.pdfViewer.currentPageNumber = page;
    }
  };

  const byPage = (items) =>
    [...items].sort((a, b) => {
      if (a.page !== b.page) return a.page - b.page;
      return String(a.createdAt || "").localeCompare(String(b.createdAt || ""));
    });

  const getPageNotes = (page) => state.notes.filter((note) => note.page === page);

  const getPageBookmark = (page) => state.bookmarks.find((bookmark) => bookmark.page === page);

  const buildPanel = () => {
    const panel = document.createElement("aside");
    panel.id = "yaReaderPanel";
    panel.setAttribute("aria-hidden", "true");
    panel.innerHTML = `
      <div class="yaReaderPanelHeader">
        <span>Notlar ve ayraçlar</span>
        <button type="button" class="yaReaderPanelClose" id="yaReaderPanelClose" title="Kapat">x</button>
      </div>
      <div class="yaReaderPanelBody">
        <div class="yaReaderCurrent" id="yaReaderCurrent"></div>
        <textarea id="yaReaderNoteInput" placeholder="Bu sayfa için not yazın"></textarea>
        <div class="yaReaderActions">
          <button type="button" class="yaReaderAction primary" id="yaReaderSaveNote">Notu Kaydet</button>
          <button type="button" class="yaReaderAction" id="yaReaderToggleBookmark">Ayraç Ekle</button>
        </div>
        <div class="yaReaderSectionTitle">Ayraçlar</div>
        <div id="yaReaderBookmarkList"></div>
        <div class="yaReaderSectionTitle">Notlar</div>
        <div id="yaReaderNoteList"></div>
      </div>
    `;
    document.body.appendChild(panel);
  };

  const addToolbarButton = (id, label, title, beforeElement) => {
    if (document.getElementById(id)) return document.getElementById(id);
    const button = document.createElement("button");
    button.id = id;
    button.type = "button";
    button.className = "toolbarButton yaToolButton";
    button.title = title;
    button.innerHTML = `<span>${escapeHtml(label)}</span>`;
    beforeElement.parentNode.insertBefore(button, beforeElement);
    return button;
  };

  const renderLists = () => {
    const page = currentPage();
    const pageNotes = getPageNotes(page);
    const hasBookmark = Boolean(getPageBookmark(page));

    document.getElementById("yaReaderCurrent").textContent = `Aktif sayfa: ${page}`;
    document.getElementById("yaReaderToggleBookmark").textContent = hasBookmark
      ? "Ayracı Kaldır"
      : "Ayraç Ekle";
    document.getElementById("yaBookmarkButton")?.classList.toggle("is-active", hasBookmark);
    document.getElementById("yaNoteButton")?.classList.toggle("is-active", pageNotes.length > 0);

    const bookmarkList = document.getElementById("yaReaderBookmarkList");
    bookmarkList.innerHTML = state.bookmarks.length
      ? byPage(state.bookmarks)
          .map(
            (bookmark) => `
              <div class="yaReaderItem" data-id="${escapeHtml(bookmark.id)}">
                <div class="yaReaderItemTop">
                  <button type="button" class="yaReaderPageButton" data-page="${bookmark.page}">Sayfa ${bookmark.page}</button>
                  <button type="button" class="yaReaderDelete" data-delete-bookmark="${escapeHtml(bookmark.id)}">Sil</button>
                </div>
                <div class="yaReaderText">${escapeHtml(bookmark.label || "Ayraç")}</div>
              </div>
            `
          )
          .join("")
      : `<div class="yaReaderEmpty">Henüz ayraç yok.</div>`;

    const noteList = document.getElementById("yaReaderNoteList");
    noteList.innerHTML = state.notes.length
      ? byPage(state.notes)
          .map(
            (note) => `
              <div class="yaReaderItem" data-id="${escapeHtml(note.id)}">
                <div class="yaReaderItemTop">
                  <button type="button" class="yaReaderPageButton" data-page="${note.page}">Sayfa ${note.page}</button>
                  <button type="button" class="yaReaderDelete" data-delete-note="${escapeHtml(note.id)}">Sil</button>
                </div>
                <div class="yaReaderText">${escapeHtml(note.text)}</div>
              </div>
            `
          )
          .join("")
      : `<div class="yaReaderEmpty">Henüz not yok.</div>`;

    renderPageBadges();
  };

  const openPanel = () => {
    const panel = document.getElementById("yaReaderPanel");
    panel.classList.add("is-open");
    panel.setAttribute("aria-hidden", "false");
    renderLists();
  };

  const closePanel = () => {
    const panel = document.getElementById("yaReaderPanel");
    panel.classList.remove("is-open");
    panel.setAttribute("aria-hidden", "true");
  };

  const saveNote = () => {
    const input = document.getElementById("yaReaderNoteInput");
    const text = input.value.trim();
    if (!text) return;
    const now = new Date().toISOString();
    state.notes.push({
      id: `${Date.now()}-${Math.random().toString(16).slice(2)}`,
      page: currentPage(),
      text,
      createdAt: now,
      updatedAt: now,
    });
    input.value = "";
    save();
    renderLists();
  };

  const toggleBookmark = () => {
    const page = currentPage();
    const existing = getPageBookmark(page);
    if (existing) {
      state.bookmarks = state.bookmarks.filter((bookmark) => bookmark.id !== existing.id);
    } else {
      state.bookmarks.push({
        id: `${Date.now()}-${Math.random().toString(16).slice(2)}`,
        page,
        label: `Sayfa ${page}`,
        createdAt: new Date().toISOString(),
      });
    }
    save();
    renderLists();
  };

  const renderPageBadges = () => {
    document.querySelectorAll(".yaPageToolBadges").forEach((node) => node.remove());
    const pages = new Set([
      ...state.bookmarks.map((bookmark) => bookmark.page),
      ...state.notes.map((note) => note.page),
    ]);
    pages.forEach((page) => {
      const pageNode = document.querySelector(`.page[data-page-number="${page}"]`);
      if (!pageNode) return;
      const badges = document.createElement("div");
      badges.className = "yaPageToolBadges";
      if (getPageBookmark(page)) {
        const badge = document.createElement("span");
        badge.className = "yaPageToolBadge bookmark";
        badge.textContent = "A";
        badges.appendChild(badge);
      }
      const noteCount = getPageNotes(page).length;
      if (noteCount) {
        const badge = document.createElement("span");
        badge.className = "yaPageToolBadge";
        badge.textContent = `N${noteCount > 1 ? noteCount : ""}`;
        badges.appendChild(badge);
      }
      pageNode.appendChild(badges);
    });
  };

  const bindPanelEvents = () => {
    document.getElementById("yaReaderPanelClose").addEventListener("click", closePanel);
    document.getElementById("yaReaderSaveNote").addEventListener("click", saveNote);
    document.getElementById("yaReaderToggleBookmark").addEventListener("click", toggleBookmark);
    document.getElementById("yaReaderPanel").addEventListener("click", (event) => {
      const pageButton = event.target.closest("[data-page]");
      if (pageButton) {
        goToPage(Number(pageButton.getAttribute("data-page")));
        renderLists();
        return;
      }
      const deleteNote = event.target.closest("[data-delete-note]");
      if (deleteNote) {
        const id = deleteNote.getAttribute("data-delete-note");
        state.notes = state.notes.filter((note) => note.id !== id);
        save();
        renderLists();
        return;
      }
      const deleteBookmark = event.target.closest("[data-delete-bookmark]");
      if (deleteBookmark) {
        const id = deleteBookmark.getAttribute("data-delete-bookmark");
        state.bookmarks = state.bookmarks.filter((bookmark) => bookmark.id !== id);
        save();
        renderLists();
      }
    });
  };

  const bindViewerEvents = () => {
    const app = window.PDFViewerApplication;
    const eventBus = app && app.eventBus;
    if (!eventBus || !eventBus._on) return;
    eventBus._on("pagesinit", renderLists);
    eventBus._on("pagechanging", renderLists);
    eventBus._on("pagerendered", renderPageBadges);
    eventBus._on("scalechanging", () => window.setTimeout(renderPageBadges, 60));
  };

  const bindPinchZoom = () => {
    if (window.__yaPdfPinchZoomBound) return;
    window.__yaPdfPinchZoomBound = true;

    const minScale = 0.2;
    const maxScale = 5;
    let pinch = null;

    const clampScale = (value) => Math.max(minScale, Math.min(maxScale, value));
    const getDistance = (touches) => {
      const dx = touches[0].clientX - touches[1].clientX;
      const dy = touches[0].clientY - touches[1].clientY;
      return Math.sqrt(dx * dx + dy * dy);
    };
    const getMidpoint = (touches) => ({
      x: (touches[0].clientX + touches[1].clientX) / 2,
      y: (touches[0].clientY + touches[1].clientY) / 2,
    });
    const getViewer = () => window.PDFViewerApplication?.pdfViewer || null;
    const getContainer = () => document.getElementById("viewerContainer");
    const isInsideContainer = (point, container) => {
      const rect = container.getBoundingClientRect();
      return (
        point.x >= rect.left &&
        point.x <= rect.right &&
        point.y >= rect.top &&
        point.y <= rect.bottom
      );
    };
    const stopNativePinch = (event) => {
      event.preventDefault();
      event.stopPropagation();
      if (typeof event.stopImmediatePropagation === "function") {
        event.stopImmediatePropagation();
      }
    };
    const setScaleWithoutJump = (viewer, scale) => {
      const nextScale = clampScale(scale);
      if (typeof viewer._setScaleUpdatePages === "function") {
        viewer._setScaleUpdatePages(nextScale, String(nextScale), true, false);
      } else {
        viewer.currentScaleValue = String(nextScale);
      }
      return nextScale;
    };
    const restoreAnchor = () => {
      if (!pinch) return;
      const container = getContainer();
      if (!container) return;
      container.scrollLeft = pinch.contentX * pinch.lastScale - pinch.localX;
      container.scrollTop = pinch.contentY * pinch.lastScale - pinch.localY;
    };

    const container = getContainer();
    if (container) {
      container.style.touchAction = "pan-x pan-y";
      container.style.webkitOverflowScrolling = "touch";
    }

    document.addEventListener(
      "touchstart",
      (event) => {
        if (event.touches.length !== 2) return;
        const viewer = getViewer();
        const container = getContainer();
        if (!viewer || !container) return;
        const point = getMidpoint(event.touches);
        if (!isInsideContainer(point, container)) return;

        stopNativePinch(event);
        const rect = container.getBoundingClientRect();
        const startScale = viewer.currentScale || 1;
        const localX = point.x - rect.left;
        const localY = point.y - rect.top;
        pinch = {
          startDistance: getDistance(event.touches),
          startScale,
          lastScale: startScale,
          localX,
          localY,
          contentX: (container.scrollLeft + localX) / startScale,
          contentY: (container.scrollTop + localY) / startScale,
        };
      },
      { capture: true, passive: false }
    );

    document.addEventListener(
      "touchmove",
      (event) => {
        if (!pinch || event.touches.length !== 2 || pinch.startDistance <= 0) return;
        const viewer = getViewer();
        if (!viewer) return;

        stopNativePinch(event);
        const ratio = getDistance(event.touches) / pinch.startDistance;
        const nextScale = clampScale(pinch.startScale * ratio);
        if (Math.abs(nextScale - pinch.lastScale) < 0.01) return;
        pinch.lastScale = setScaleWithoutJump(viewer, nextScale);
        window.requestAnimationFrame(restoreAnchor);
      },
      { capture: true, passive: false }
    );

    const clearPinch = (event) => {
      if (!event || event.touches.length < 2) {
        pinch = null;
      }
    };
    document.addEventListener("touchend", clearPinch, {
      capture: true,
      passive: false,
    });
    document.addEventListener(
      "touchcancel",
      () => {
        pinch = null;
      },
      { capture: true, passive: false }
    );
    document.addEventListener("gesturestart", stopNativePinch, {
      capture: true,
      passive: false,
    });
    document.addEventListener("gesturechange", stopNativePinch, {
      capture: true,
      passive: false,
    });
  };

  const init = () => {
    if (document.getElementById("yaReaderPanel")) return;
    const toolsButton = document.getElementById("secondaryToolbarToggle");
    if (!toolsButton) return;

    load();
    buildPanel();

    const bookmarkButton = addToolbarButton("yaBookmarkButton", "Ayraç", "Bu sayfaya ayraç ekle", toolsButton);
    const noteButton = addToolbarButton("yaNoteButton", "Not", "Bu sayfaya not ekle", toolsButton);
    const panelButton = addToolbarButton("yaPanelButton", "Liste", "Not ve ayraç listesini aç", toolsButton);

    bookmarkButton.addEventListener("click", toggleBookmark);
    noteButton.addEventListener("click", () => {
      openPanel();
      document.getElementById("yaReaderNoteInput").focus();
    });
    panelButton.addEventListener("click", openPanel);

    bindPanelEvents();
    bindViewerEvents();
    bindPinchZoom();
    renderLists();
  };

  const boot = () => {
    const app = window.PDFViewerApplication;
    if (app && app.initializedPromise) {
      app.initializedPromise.then(init).catch(init);
    } else {
      window.setTimeout(boot, 50);
    }
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
