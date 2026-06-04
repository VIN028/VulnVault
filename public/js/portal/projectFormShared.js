(function () {
  'use strict';
  
  const { escA } = window.PortalShared || {};

  function addProjectLink(containerId, title = '', url = '') {
    const container = document.getElementById(containerId);
    if (!container) return;
    const id = 'link-row-' + Date.now() + Math.random().toString(36).substr(2, 5);
    const div = document.createElement('div');
    div.id = id;
    div.style = 'display:flex;gap:8px;align-items:center;';
    div.innerHTML = `
      <input class="cp-link-title" placeholder="e.g. Jira Issue" value="${escA ? escA(title) : title}" style="flex:1;padding:8px 12px;font-size:12px;">
      <input class="cp-link-url" placeholder="e.g. https://..." value="${escA ? escA(url) : url}" style="flex:2;padding:8px 12px;font-size:12px;">
      <button type="button" class="icon-btn js-remove-project-link" data-id="${id}" style="color:var(--red);flex:none;padding:8px;">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="width:14px;height:14px;"><line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" /></svg>
      </button>
    `;
    container.appendChild(div);
  }

  function collectProjectLinks(containerId) {
    const links = [];
    const container = document.getElementById(containerId);
    if (!container) return links;
    container.querySelectorAll(':scope > div').forEach(row => {
      const titleInput = row.querySelector('.cp-link-title');
      const urlInput = row.querySelector('.cp-link-url');
      if (titleInput && urlInput) {
        const title = titleInput.value.trim();
        const url = urlInput.value.trim();
        if (title || url) links.push({ title, url });
      }
    });
    return links;
  }

  window.ProjectFormShared = {
    addProjectLink,
    collectProjectLinks
  };
})();
