'use strict';

const path = require('path');
const express = require('express');
const expressWs = require('express-ws');
const { handleConnection } = require('./lib/rdp-proxy');

const PORT = parseInt(process.env.PORT || '8080', 10);
const ROOT = __dirname;

const app = express();
expressWs(app);

// ── Static file serving ──

app.use('/pkg', express.static(path.join(ROOT, '..', 'pkg'), {
    setHeaders(res, filePath) {
        if (filePath.endsWith('.wasm')) res.setHeader('Content-Type', 'application/wasm');
    },
}));

// Root → index.html
app.get('/', (_req, res) => {
    res.sendFile(path.join(ROOT, 'index.html'));
});

// ── WebSocket RDCleanPath proxy ──
// The WASM client connects to ws://<host>:<port>/
// express-ws handles the upgrade; we delegate to lib/rdp-proxy.

app.ws('/', (ws, _req) => {
    handleConnection(ws);
});

// ── Start ──

app.listen(PORT, () => {
    console.log(`\n  🚀 RDCleanPath proxy + HTTP server on http://localhost:${PORT}/`);
    console.log(`  📂 Serving files from ${ROOT}`);
    console.log(`  🔌 WebSocket proxy on ws://localhost:${PORT}/\n`);
});
