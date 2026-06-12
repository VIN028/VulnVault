(function () {
  'use strict';

  const { esc, apiFetch, showToast } = window.PortalShared || {};

  // Drag/drop for reordering status setup tiles (not project cards)
  function reorderStatusByDrag(e, targetIdx, boardStatuses, onReorderSuccess) {
    e.preventDefault();
    const sourceIdx = parseInt(e.dataTransfer.getData('text/plain'));
    if (isNaN(sourceIdx) || sourceIdx === targetIdx) return;
    
    const [moved] = boardStatuses.splice(sourceIdx, 1);
    boardStatuses.splice(targetIdx, 0, moved);
    if (typeof onReorderSuccess === 'function') onReorderSuccess();
  }

  function renderSetupList(listEl, boardStatuses, onReorder) {
    if (!listEl) return;
    listEl.innerHTML = '';

    if (!boardStatuses || !boardStatuses.length) {
      listEl.innerHTML = '<div style="padding:12px; text-align:center; color:var(--muted); font-size:12px;">No custom status columns. Add one below.</div>';
      return;
    }

    boardStatuses.forEach((s, idx) => {
      const tile = document.createElement('div');
      tile.className = 'status-setup-tile';
      tile.draggable = true;
      tile.ondragstart = (ev) => ev.dataTransfer.setData('text/plain', idx);
      tile.ondragover = (ev) => ev.preventDefault();
      tile.ondrop = (ev) => reorderStatusByDrag(ev, idx, boardStatuses, onReorder);
      tile.style = `display:flex; align-items:center; justify-content:space-between; padding:10px 14px; background:rgba(255,255,255,0.02); border:1px solid var(--border); border-radius:8px; cursor:grab; margin-bottom:6px;`;
      tile.innerHTML = `
        <div style="display:flex; align-items:center; gap:10px; font-size:12px; font-weight:700; flex-wrap:wrap;">
          <span style="color:var(--muted);">⋮⋮</span>
          <span style="display:block; width:10px; height:10px; border-radius:50%; background:${s.color || '#6366f1'};"></span>
          <span>${esc ? esc(s.name) : s.name}</span>
          <label style="font-size:10px; font-weight:normal; margin-left:12px; display:inline-flex; align-items:center; gap:4px; cursor:pointer; color:var(--muted);">
            <input type="checkbox" class="js-status-terminal" data-id="${s.id}" ${s.is_terminal ? 'checked' : ''}>
            Final stage
          </label>
        </div>
        <button class="icon-btn js-delete-board-status" data-id="${s.id}" style="color:var(--red); padding:4px;">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="width:13px;height:13px;"><line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" /></svg>
        </button>
      `;
      listEl.appendChild(tile);
    });
  }

  function closeFloatingMenu(selector = '.quick-move-menu') {
    document.querySelector(selector)?.remove();
  }

  function positionFloatingMenu(menu, anchorEl) {
    const rect = anchorEl.getBoundingClientRect();
    const gap = 6;
    const viewportPadding = 12;

    menu.style.top = '0px';
    menu.style.left = '0px';
    menu.style.visibility = 'hidden';

    const menuRect = menu.getBoundingClientRect();

    let top = rect.bottom + gap;
    let left = rect.left;

    if (top + menuRect.height > window.innerHeight - viewportPadding) {
      top = rect.top - menuRect.height - gap;
    }

    if (left + menuRect.width > window.innerWidth - viewportPadding) {
      left = window.innerWidth - menuRect.width - viewportPadding;
    }

    if (left < viewportPadding) {
      left = viewportPadding;
    }

    if (top < viewportPadding) {
      top = viewportPadding;
    }

    menu.style.top = `${top}px`;
    menu.style.left = `${left}px`;
    menu.style.visibility = 'visible';
  }

  window.BoardShared = {
    reorderStatusByDrag,
    reorderStatus: reorderStatusByDrag, // backward-compatible alias
    renderSetupList,
    closeFloatingMenu,
    positionFloatingMenu
  };
})();
