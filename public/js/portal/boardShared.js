(function () {
  'use strict';

  const { esc, apiFetch, showToast } = window.PortalShared || {};

  function onCardDragStart(e, projectId) {
    e.dataTransfer.setData('text/plain', projectId);
  }

  function onCardDragOver(e) {
    e.preventDefault();
  }

  async function handleCardDrop(e, colId, onDropSuccess) {
    e.preventDefault();
    const projId = e.dataTransfer.getData('text/plain');
    if (!projId) return;
    
    try {
      await apiFetch(`/api/projects/${projId}/board-status`, 'PATCH', { board_status_id: colId === -1 ? null : colId });
      if (typeof onDropSuccess === 'function') onDropSuccess();
    } catch (err) {
      if (showToast) showToast('Failed to update board status: ' + err.message, 'error');
    }
  }

  function reorderStatus(e, targetIdx, boardStatuses, onReorderSuccess) {
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
      tile.ondrop = (ev) => reorderStatus(ev, idx, boardStatuses, onReorder);
      tile.style = `display:flex; align-items:center; justify-content:space-between; padding:10px 14px; background:rgba(255,255,255,0.02); border:1px solid var(--border); border-radius:8px; cursor:grab; margin-bottom:6px;`;
      tile.innerHTML = `
        <div style="display:flex; align-items:center; gap:10px; font-size:12px; font-weight:700;">
          <span style="color:var(--muted);">⋮⋮</span>
          <span style="display:block; width:10px; height:10px; border-radius:50%; background:${s.color || '#6366f1'};"></span>
          <span>${esc ? esc(s.name) : s.name}</span>
        </div>
        <button class="icon-btn js-delete-board-status" data-id="${s.id}" style="color:var(--red); padding:4px;">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="width:13px;height:13px;"><line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" /></svg>
        </button>
      `;
      listEl.appendChild(tile);
    });
  }

  window.BoardShared = {
    onCardDragStart,
    onCardDragOver,
    handleCardDrop,
    reorderStatus,
    renderSetupList
  };
})();
