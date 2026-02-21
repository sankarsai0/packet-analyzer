/* ════════════════════════════════════════════
   PacketScope — app.js
   Frontend logic: SSE capture, upload, filter,
   packet table, detail inspector, stats chart
════════════════════════════════════════════ */

"use strict";

// ── State ──────────────────────────────────────────
let allPackets = [];      // all received packets (capped at MAX_DISPLAY)
let filtered = [];        // indices into allPackets matching current filter
let eventSrc = null;      // EventSource for live capture
let capturing = false;
let selectedIdx = -1;

// Cache frequently-used DOM elements after DOMContentLoaded
let _tbody = null;
let _totalCountEl = null;
let _filterCountEl = null;
let _filterInputEl = null;
let _filterProtoEl = null;
let _emptyStateEl = null;

// Protocol → color (matches CSS vars)
const PROTO_COLORS = {
    TCP: '#38beff',
    UDP: '#2ee89a',
    HTTP: '#ff9f57',
    HTTPS: '#ff9f57',
    HTTP2: '#ff9f57',
    DNS: '#ffd166',
    TLS: '#a78bfa',
    SSL: '#a78bfa',
    ICMP: '#ff4d6d',
    ICMPV6: '#ff4d6d',
    ARP: '#c084fc',
    IPV6: '#2dd4bf',
    DHCP: '#f472b6',
    BOOTP: '#f472b6',
};

// Known protocol classes that have CSS rules defined
const KNOWN_PROTOS = new Set(Object.keys(PROTO_COLORS));

function protoColor(p) {
    return PROTO_COLORS[p?.toUpperCase()] || '#94a3b8';
}

// ── Init ───────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    // Cache DOM refs once
    _tbody = document.getElementById('packetBody');
    _totalCountEl = document.getElementById('totalCount');
    _filterCountEl = document.getElementById('filterCount');
    _filterInputEl = document.getElementById('filterInput');
    _filterProtoEl = document.getElementById('filterProto');
    _emptyStateEl = document.getElementById('emptyState');

    initChart();
    loadInterfaces();
    checkTshark();
    setupDrop();
});

// ── tshark health check ────────────────────────────
async function checkTshark() {
    const badge = document.getElementById('tsharkBadge');
    try {
        const r = await fetch('/api/tshark-check');
        const d = await r.json();
        if (d.ok) {
            badge.title = d.version + ' @ ' + d.path;
        } else {
            badge.classList.add('error');
            badge.querySelector('span').textContent = 'tshark missing';
            badge.title = d.error;
        }
    } catch {
        badge.classList.add('error');
        badge.querySelector('span').textContent = 'tshark error';
    }
}

// ── Interface selector ─────────────────────────────
async function loadInterfaces() {
    try {
        const r = await fetch('/api/interfaces');
        const d = await r.json();
        const sel = document.getElementById('ifaceSelect');
        sel.innerHTML = '';
        if (d.interfaces && d.interfaces.length) {
            d.interfaces.forEach(iface => {
                const opt = document.createElement('option');
                // value = numeric id (passed to tshark -i)
                opt.value = iface.id;
                // Display only the friendly name
                opt.textContent = iface.name;
                opt.title = `Interface ${iface.id}: ${iface.name}`;
                sel.appendChild(opt);
            });
        } else {
            sel.innerHTML = '<option value="1">Default (1)</option>';
        }
    } catch {
        document.getElementById('ifaceSelect').innerHTML =
            '<option value="1">Default (1)</option>';
    }
}

// ── Live Capture ───────────────────────────────────
async function startCapture() {
    const iface = document.getElementById('ifaceSelect').value;
    setStatus('Starting…', 'idle');

    try {
        const r = await fetch('/api/capture/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ interface: iface }),
        });

        const text = await r.text();
        let d;
        try {
            d = JSON.parse(text);
        } catch (je) {
            console.error("Malformed JSON response:", text);
            // Check if it's the localtunnel landing page
            if (text.includes("localtunnel")) {
                throw new Error("Localtunnel 'Bypass' page detected. Please open the URL in your browser first and click 'Bypass'.");
            }
            throw new Error("Server sent invalid data. Check console for details.");
        }

        if (!r.ok) {
            const msg = d.error || 'Failed to start capture';
            setStatus('Error: ' + msg, 'error');
            alert('⚠️ Capture Error:\n\n' + msg);
            return;
        }
    } catch (e) {
        setStatus('Error: ' + e.message, 'error');
        alert('⚠️ Capture Error:\n\n' + e.message);
        return;
    }

    capturing = true;
    document.getElementById('controlPanel').classList.add('capturing');
    document.getElementById('btnStart').disabled = true;
    document.getElementById('btnStop').disabled = false;
    setStatus('Capturing', 'running');

    // Open SSE
    if (eventSrc) { eventSrc.close(); }
    eventSrc = new EventSource('/api/stream');
    eventSrc.onmessage = (e) => {
        try {
            if (!e.data || e.data.trim() === '') return;
            const data = JSON.parse(e.data);
            if (data.connected) return;
            queueLivePacket(data);
        } catch (err) {
            console.warn("SSE Parse Error:", err, "Data:", e.data);
        }
    };
    eventSrc.onerror = () => {
        if (capturing) {
            setStatus('Stream error', 'error');
        }
    };
}

async function stopCapture() {
    capturing = false;
    document.getElementById('controlPanel').classList.remove('capturing');
    if (eventSrc) { eventSrc.close(); eventSrc = null; }
    document.getElementById('btnStart').disabled = false;
    document.getElementById('btnStop').disabled = true;
    setStatus('Idle', 'idle');
    try {
        await fetch('/api/capture/stop', { method: 'POST' });
    } catch { }
}

// ── Upload PCAP ────────────────────────────────────
async function uploadFile(file) {
    if (!file) return;

    clearPackets();
    const prog = document.getElementById('uploadProgress');
    const fill = document.getElementById('progressFill');
    const stat = document.getElementById('uploadStatus');
    prog.hidden = false;
    fill.style.width = '30%';
    stat.textContent = 'Uploading…';
    setStatus('Parsing file…', 'idle');

    const fd = new FormData();
    fd.append('file', file);

    try {
        const r = await fetch('/api/upload', { method: 'POST', body: fd });
        fill.style.width = '70%';
        stat.textContent = 'Parsing packets…';
        const d = await r.json();

        if (!r.ok) {
            stat.textContent = 'Error: ' + (d.error || 'Failed');
            setStatus('Error', 'error');
            return;
        }

        // Render packets incrementally so the browser doesn't freeze
        _renderPacketsChunked(d.packets, d.sessionId || null, fill, stat, prog);
    } catch (e) {
        stat.textContent = 'Error: ' + e.message;
        setStatus('Error', 'error');
    }
}

// Render an array of packets in chunks per animation frame
const RENDER_CHUNK = 500;

function _renderPacketsChunked(packets, sessionId, fill, stat, prog) {
    const total = packets.length;
    let i = 0;

    // Grab current filter state once (it won't change during initial load)
    const query = _filterInputEl.value.trim().toLowerCase();
    const proto = _filterProtoEl.value.toUpperCase();
    const hasFilter = !!(query || proto);

    function renderNext() {
        if (i >= total) {
            fill.style.width = '100%';
            stat.textContent = `Loaded ${total} packets`;
            setStatus('File loaded', 'idle');
            _flushStatsNow();
            setTimeout(() => { prog.hidden = true; fill.style.width = '0%'; }, 1500);
            return;
        }

        if (_emptyStateEl) _emptyStateEl.style.display = 'none';
        const frag = document.createDocumentFragment();

        const end = Math.min(i + RENDER_CHUNK, total);
        for (; i < end; i++) {
            const pkt = packets[i];
            if (sessionId) {
                pkt.sessionId = sessionId;
                pkt.idx = i;
            }
            allPackets.push(pkt);
            const matches = !hasFilter || packetMatchesFilter(pkt, query, proto);
            const rowIdx = allPackets.length - 1;
            const tr = _buildRow(pkt, rowIdx, matches);
            if (matches) filtered.push(pkt);
            _statsIncrement(pkt);
            frag.appendChild(tr);
        }

        _tbody.appendChild(frag);
        _totalCountEl.textContent = allPackets.length;
        updateFilterCount();

        fill.style.width = (70 + Math.round((i / total) * 29)) + '%';
        stat.textContent = `Rendering… ${i} / ${total}`;

        requestAnimationFrame(renderNext);
    }

    requestAnimationFrame(renderNext);
}

// ── Add packet to state + table ────────────────────
const MAX_DISPLAY = 5000;  // increased; pruning is now O(1)

// addPacket is kept for API compatibility but live path uses processLiveQueue
function addPacket(pkt, doFilter = true) {
    allPackets.push(pkt);
    if (allPackets.length > MAX_DISPLAY) allPackets.shift();
    _totalCountEl.textContent = allPackets.length;

    if (!doFilter || packetMatchesFilter(pkt)) {
        const tr = _buildRow(pkt, allPackets.length - 1, true);
        _tbody.appendChild(tr);
        filtered.push(pkt);
        updateFilterCount();
    }
    _statsIncrement(pkt);
}

// ── Table rendering ────────────────────────────────
// Build a <tr> element. hidden=true means it doesn't match the current filter.
function _buildRow(pkt, idx, visible = true) {
    const proto = (pkt.protocol || 'UNKNOWN').toUpperCase();
    const cls = KNOWN_PROTOS.has(proto) ? proto : 'default';

    const tr = document.createElement('tr');
    tr.className = `row-${proto}`;
    tr.dataset.idx = idx;
    // Store searchable text as a data attribute for fast show/hide filtering
    tr.dataset.filter = [
        pkt.src, pkt.dst, pkt.protocol, pkt.info,
        pkt.number, pkt.length
    ].join('\x00').toLowerCase();
    tr.dataset.proto = proto;
    if (!visible) tr.classList.add('row-hidden');

    // Use textContent (safe, faster) for user-content cells
    const tdNo = document.createElement('td'); tdNo.className = 'td-no'; tdNo.textContent = pkt.number || idx + 1;
    const tdTime = document.createElement('td'); tdTime.className = 'td-time'; tdTime.textContent = parseFloat(pkt.time || 0).toFixed(4);
    const tdSrc = document.createElement('td'); tdSrc.title = pkt.src || ''; tdSrc.textContent = pkt.src || '—';
    const tdDst = document.createElement('td'); tdDst.title = pkt.dst || ''; tdDst.textContent = pkt.dst || '—';
    const badge = document.createElement('span'); badge.className = `proto-badge proto-${cls}`; badge.textContent = proto;
    const tdPro = document.createElement('td'); tdPro.appendChild(badge);
    const tdLen = document.createElement('td'); tdLen.textContent = pkt.length || '';
    const tdInfo = document.createElement('td'); tdInfo.className = 'td-info'; tdInfo.title = pkt.info || ''; tdInfo.textContent = pkt.info || '';

    tr.append(tdNo, tdTime, tdSrc, tdDst, tdPro, tdLen, tdInfo);
    tr.addEventListener('click', () => selectRow(tr, pkt));
    return tr;
}

// ── Optimized Live Rendering ───────────────────────
let livePacketQueue = [];
let liveRenderTimer = null;
const RENDER_MAX_LIVE = 200; // packets per rAF frame

function queueLivePacket(pkt) {
    livePacketQueue.push(pkt);
    if (!liveRenderTimer) {
        liveRenderTimer = requestAnimationFrame(processLiveQueue);
    }
}

function processLiveQueue() {
    if (livePacketQueue.length === 0) {
        liveRenderTimer = null;
        return;
    }

    if (_emptyStateEl) _emptyStateEl.style.display = 'none';

    const batch = livePacketQueue.splice(0, RENDER_MAX_LIVE);
    const totalNew = batch.length;

    // Prune oldest entries — splice DOM rows that are being removed
    const overflow = (allPackets.length + totalNew) - MAX_DISPLAY;
    if (overflow > 0) {
        allPackets.splice(0, overflow);
        // Remove oldest DOM rows in one loop
        let removed = 0;
        while (removed < overflow && _tbody.firstChild) {
            _tbody.removeChild(_tbody.firstChild);
            removed++;
        }
    }

    const query = _filterInputEl.value.trim().toLowerCase();
    const proto = _filterProtoEl.value.toUpperCase();
    const hasFilter = !!(query || proto);

    const frag = document.createDocumentFragment();
    batch.forEach(pkt => {
        allPackets.push(pkt);
        const matches = !hasFilter || packetMatchesFilter(pkt, query, proto);
        if (matches) filtered.push(pkt);
        _statsIncrement(pkt);
        frag.appendChild(_buildRow(pkt, allPackets.length - 1, matches));
    });

    _tbody.appendChild(frag);
    _totalCountEl.textContent = allPackets.length;
    updateFilterCount();

    const container = document.getElementById('tableContainer');
    if (container.scrollTop + container.clientHeight >= container.scrollHeight - 150) {
        container.scrollTop = container.scrollHeight;
    }

    if (livePacketQueue.length > 0) {
        liveRenderTimer = requestAnimationFrame(processLiveQueue);
    } else {
        liveRenderTimer = null;
    }
}

function appendRow(pkt, idx) {
    if (_emptyStateEl) _emptyStateEl.style.display = 'none';
    const tr = _buildRow(pkt, idx, true);
    _tbody.appendChild(tr);
    const container = document.getElementById('tableContainer');
    if (container.scrollTop + container.clientHeight >= container.scrollHeight - 60) {
        container.scrollTop = container.scrollHeight;
    }
}

function selectRow(tr, pkt) {
    // Deselect previous (limit querySelector scope for speed)
    const prev = _tbody.querySelector('tr.selected');
    if (prev) prev.classList.remove('selected');
    tr.classList.add('selected');
    showDetail(pkt);
}

function clearPackets() {
    allPackets = [];
    filtered = [];
    selectedIdx = -1;
    // Fastest DOM clear
    _tbody.textContent = '';
    _totalCountEl.textContent = '0';
    if (_emptyStateEl) _emptyStateEl.style.display = '';
    document.getElementById('detailPanel').hidden = true;
    updateFilterCount();
    resetStats();
}

// ── Filter ─────────────────────────────────────────
// Fast show/hide filter — never rebuilds the DOM, just toggles visibility.
let filterTimer = null;

function applyFilter() {
    clearTimeout(filterTimer);
    filterTimer = setTimeout(_applyFilter, 120);
}

function _applyFilter() {
    const query = _filterInputEl.value.trim().toLowerCase();
    const proto = _filterProtoEl.value.toUpperCase();
    const hasQuery = !!query;
    const hasProto = !!proto;
    filtered = [];

    // Walk existing DOM rows and toggle visibility — no row creation/deletion
    const rows = _tbody.children;
    for (let i = 0, len = rows.length; i < len; i++) {
        const tr = rows[i];
        const rowProto = tr.dataset.proto || '';
        const rowFilter = tr.dataset.filter || '';

        let visible = true;
        if (hasProto && rowProto !== proto) visible = false;
        if (visible && hasQuery && !rowFilter.includes(query)) visible = false;

        if (visible) {
            tr.classList.remove('row-hidden');
            // Recover packet ref from allPackets by idx for filtered array
            const idx = parseInt(tr.dataset.idx, 10);
            if (!isNaN(idx) && allPackets[idx]) filtered.push(allPackets[idx]);
        } else {
            tr.classList.add('row-hidden');
        }
    }

    if (_emptyStateEl) {
        _emptyStateEl.style.display = allPackets.length === 0 ? '' : 'none';
    }
    updateFilterCount();
}

function packetMatchesFilter(pkt, query, proto) {
    if (query === undefined) query = _filterInputEl.value.trim().toLowerCase();
    if (proto === undefined) proto = _filterProtoEl.value.toUpperCase();

    if (proto && pkt.protocol?.toUpperCase() !== proto) return false;
    if (!query) return true;

    // Single concatenated string search — one includes() call is fastest
    const flat = [
        pkt.src, pkt.dst, pkt.protocol, pkt.info,
        pkt.number, pkt.length
    ].join('\x00').toLowerCase();
    return flat.includes(query);
}

function clearFilter() {
    _filterInputEl.value = '';
    _filterProtoEl.value = '';
    _applyFilter();
}

function updateFilterCount() {
    const q = _filterInputEl.value.trim();
    const p = _filterProtoEl.value;
    if (q || p) {
        _filterCountEl.textContent = `${filtered.length} / ${allPackets.length} shown`;
    } else {
        _filterCountEl.textContent = '';
    }
}

// ── Detail Panel ───────────────────────────────────
async function showDetail(pkt) {
    const panel = document.getElementById('detailPanel');
    panel.hidden = false;
    document.getElementById('detailTitle').textContent =
        `Packet #${pkt.number} — ${pkt.protocol}  ${pkt.src} → ${pkt.dst}`;
    const body = document.getElementById('detailBody');
    body.innerHTML = '<span style="color:var(--text-3);font-size:12px">Loading…</span>';

    try {
        // If we have raw data already (live capture), use it directly
        if (pkt.raw) {
            body.innerHTML = '';
            body.appendChild(buildJsonTree(pkt.raw, 0));
            return;
        }
        // Otherwise lazy-fetch from the server (uploaded pcap)
        if (pkt.sessionId !== undefined && pkt.idx !== undefined) {
            const r = await fetch(`/api/packet-detail/${pkt.sessionId}/${pkt.idx}`);
            const d = await r.json();
            if (d.raw) {
                pkt.raw = d.raw; // cache so subsequent clicks are instant
                body.innerHTML = '';
                body.appendChild(buildJsonTree(d.raw, 0));
                return;
            }
        }
        body.innerHTML = '<span style="color:var(--text-3)">No detail available.</span>';
    } catch (e) {
        body.innerHTML = `<span style="color:var(--red)">${e.message}</span>`;
    }
}

function closeDetail() {
    document.getElementById('detailPanel').hidden = true;
    document.querySelectorAll('.packet-table tr.selected').forEach(r =>
        r.classList.remove('selected')
    );
}

function buildJsonTree(obj, depth) {
    const frag = document.createDocumentFragment();

    if (typeof obj === 'object' && obj !== null) {
        for (const [k, v] of Object.entries(obj)) {
            const isNested = typeof v === 'object' && v !== null;
            const wrapper = document.createElement('div');
            wrapper.style.paddingLeft = depth > 0 ? '0' : '0';

            if (isNested) {
                const toggle = document.createElement('div');
                toggle.className = 'tree-node';
                toggle.innerHTML =
                    `<span class="tree-toggle">▾</span><span class="json-key">${escHtml(k)}</span> <span style="color:var(--text-3)">{ ${Object.keys(v).length} }</span>`;
                const children = document.createElement('div');
                children.className = 'tree-children';
                children.appendChild(buildJsonTree(v, depth + 1));
                toggle.addEventListener('click', (e) => {
                    e.stopPropagation();
                    const collapsed = children.classList.toggle('collapsed');
                    toggle.querySelector('.tree-toggle').textContent = collapsed ? '▸' : '▾';
                });
                wrapper.appendChild(toggle);
                wrapper.appendChild(children);
            } else {
                const line = document.createElement('div');
                line.innerHTML =
                    `<span class="tree-toggle"> </span><span class="json-key">${escHtml(k)}</span>: ${formatJsonVal(v)}`;
                line.style.paddingLeft = `${depth * 14}px`;
                wrapper.appendChild(line);
            }

            frag.appendChild(wrapper);
        }
    } else {
        const line = document.createElement('div');
        line.innerHTML = formatJsonVal(obj);
        frag.appendChild(line);
    }

    return frag;
}

function formatJsonVal(v) {
    if (v === null) return `<span class="json-null">null</span>`;
    if (typeof v === 'boolean') return `<span class="json-bool">${v}</span>`;
    if (typeof v === 'number') return `<span class="json-num">${v}</span>`;
    return `<span class="json-str">"${escHtml(String(v))}"</span>`;
}

function escHtml(s) {
    return String(s)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;')
        .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// ── Statistics ─────────────────────────────────────
let protoStats = {};  // { PROTO: count }
let chartInstance = null;
let _statsDirty = false;
let _statsRafId = null;

function initChart() {
    const ctx = document.getElementById('protoChart').getContext('2d');
    chartInstance = new Chart(ctx, {
        type: 'doughnut',
        data: { labels: [], datasets: [{ data: [], backgroundColor: [], borderWidth: 1.5, borderColor: 'rgba(0,0,0,0.3)' }] },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: { callbacks: { label: (ctx) => ` ${ctx.label}: ${ctx.raw} pkts` } }
            },
            cutout: '72%',
            animation: false,
        }
    });
}

// Accumulate stat without scheduling a render every packet
function _statsIncrement(pkt) {
    const proto = (pkt.protocol || 'UNKNOWN').toUpperCase();
    protoStats[proto] = (protoStats[proto] || 0) + 1;
    if (!_statsDirty) {
        _statsDirty = true;
        // Coalesce renders into one per rAF tick
        if (!_statsRafId) _statsRafId = requestAnimationFrame(_statsRAF);
    }
}

function _statsRAF() {
    _statsRafId = null;
    if (_statsDirty) { _statsDirty = false; renderStats(); }
}

// Keep old name for any callers
function updateStatsIncremental(pkt) { _statsIncrement(pkt); }

function _flushStatsNow() { _statsDirty = false; renderStats(); }

function updateStats() {
    protoStats = {};
    for (const p of allPackets) {
        const proto = (p.protocol || 'UNKNOWN').toUpperCase();
        protoStats[proto] = (protoStats[proto] || 0) + 1;
    }
    renderStats();
}

function renderStats() {
    const sorted = Object.entries(protoStats).sort((a, b) => b[1] - a[1]);
    const labels = sorted.map(e => e[0]);
    const values = sorted.map(e => e[1]);
    const colors = labels.map(l => protoColor(l));
    const total = values.reduce((a, b) => a + b, 0) || 1;

    // Update chart
    chartInstance.data.labels = labels;
    chartInstance.data.datasets[0].data = values;
    chartInstance.data.datasets[0].backgroundColor = colors;
    chartInstance.update('none');

    // Update stats list
    const list = document.getElementById('statsList');
    list.innerHTML = '';
    sorted.slice(0, 12).forEach(([proto, count]) => {
        const pct = Math.round((count / total) * 100);
        const color = protoColor(proto);
        const row = document.createElement('div');
        row.className = 'stat-row';
        row.innerHTML = `
      <div class="stat-dot" style="background:${color}"></div>
      <span class="stat-name">${proto}</span>
      <div class="stat-bar-wrap"><div class="stat-bar" style="width:${pct}%;background:${color}88"></div></div>
      <span class="stat-count">${count}</span>
    `;
        list.appendChild(row);
    });
}

function resetStats() {
    protoStats = {};
    if (chartInstance) {
        chartInstance.data.labels = [];
        chartInstance.data.datasets[0].data = [];
        chartInstance.update('none');
    }
    document.getElementById('statsList').innerHTML = '';
}

// ── Status indicator ───────────────────────────────
function setStatus(text, state) {
    document.getElementById('statusText').textContent = text;
    const dot = document.getElementById('statusDot');
    dot.className = 'status-dot';
    if (state !== 'idle') dot.classList.add(state);
}

// ── Drag and Drop for upload ───────────────────────
function setupDrop() {
    const zone = document.getElementById('dropZone');
    zone.addEventListener('dragover', e => {
        e.preventDefault();
        zone.classList.add('drag-over');
    });
    zone.addEventListener('dragleave', () => zone.classList.remove('drag-over'));
    zone.addEventListener('drop', e => {
        e.preventDefault();
        zone.classList.remove('drag-over');
        const file = e.dataTransfer.files[0];
        if (file) uploadFile(file);
    });
}
