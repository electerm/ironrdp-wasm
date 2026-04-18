<div align="center">

# IronRDP WASM

[![English](https://img.shields.io/badge/English-README-blue)](README.md)
[![中文](https://img.shields.io/badge/中文-说明-red)](README.zh-CN.md)

WebAssembly build of [IronRDP](https://github.com/Devolutions/IronRDP) for browser-based RDP clients.

</div>

## Features

- **RDP Connection** - Connect to RDP servers directly from the browser
- **Input Handling** - Keyboard, mouse, and wheel support with PS/2 Set 1 scancode mapping
- **Clipboard Sync** - Text clipboard synchronization between local and remote
- **File Transfer** - Upload and download files via CLIPRDR channel
  - Drag & drop or file picker to upload files to remote desktop
  - Download files copied on remote server explorer
- **WebSocket Proxy** - Example proxy server (`example/lib/rdp-proxy.js`) for RDCleanPath protocol

## Quick Start

```bash
npm install
npm run build
npm run example
```

Open http://localhost:8080 in your browser.

## Project Structure

```
ironrdp-wasm/
├── src/
│   └── lib.rs              # Rust WASM bindings
├── pkg/                    # Build output (generated)
│   ├── rdp_client.js       # JavaScript bindings
│   ├── rdp_client_bg.wasm  # Compiled WebAssembly
│   └── rdp_client.d.ts     # TypeScript definitions
├── example/
│   ├── index.html          # Demo RDP client UI
│   ├── style.css           # Styles
│   ├── server.js           # HTTP + WebSocket proxy server
│   └── lib/
│       ├── logger.js       # Logging and status utilities
│       ├── input.js        # Keyboard/mouse input handlers
│       ├── clipboard.js    # Clipboard synchronization
│       ├── file-transfer.js # File upload/download via CLIPRDR
│       ├── session.js      # Session manager (ties everything together)
│       └── rdp-proxy.js    # WebSocket RDCleanPath proxy
├── Cargo.toml
└── package.json
```

## Prerequisites

### Rust Toolchain

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup target add wasm32-unknown-unknown
```

### wasm-pack

```bash
cargo install wasm-pack
```

### Node.js

Node.js 16+ from [nodejs.org](https://nodejs.org/) or via [nvm](https://github.com/nvm-sh/nvm).

## Building

```bash
npm install
npm run build
```

This runs `wasm-pack build --target web --out-dir pkg --release`, producing:
- `pkg/rdp_client.js` - JavaScript bindings
- `pkg/rdp_client_bg.wasm` - Compiled WebAssembly
- `pkg/rdp_client.d.ts` - TypeScript definitions

For debug builds:
```bash
wasm-pack build --target web --out-dir pkg --dev
```

## Usage

```javascript
import init, {
    SessionBuilder,
    DesktopSize,
    Extension,
    DeviceEvent,
    InputTransaction,
    ClipboardData,
} from 'ironrdp-wasm';

await init();

const builder = new SessionBuilder();
builder.username('user');
builder.password('pass');
builder.destination('rdp-server:3389');
builder.proxyAddress('ws://localhost:8080');
builder.desktopSize(new DesktopSize(1280, 720));
builder.renderCanvas(canvasElement);

const session = await builder.connect();
session.run();
```

### Extensions

IronRDP uses an extension system for optional features:

```javascript
// Enable CredSSP
builder.extension(new Extension('enable_credssp', true));

// File transfer callbacks
builder.extension(new Extension('files_available_callback', (files, clipDataId) => {
    // Remote has files available for download
}));

// Clipboard callbacks
builder.remoteClipboardChangedCallback((clipboardData) => {
    // Remote clipboard changed
});

builder.forceClipboardUpdateCallback(() => {
    // Sync local clipboard to remote
});
```

## Example Application

The `example/` folder contains a complete demo with:
- Modern dark-themed UI with connection bar, canvas, log panel, and file transfer panel
- Modular JavaScript architecture (`logger.js`, `input.js`, `clipboard.js`, `file-transfer.js`, `session.js`)
- WebSocket proxy server for RDCleanPath protocol

To run:
```bash
cd example && npm install && cd ..
npm run build
npm run example
```

## Credits

This package is a WebAssembly compilation of [Marc-André Moreau's IronRDP library](https://github.com/Devolutions/IronRDP). All RDP protocol implementation and core functionality is from the original IronRDP project. This package provides the build tooling and JavaScript bindings to make IronRDP available for web projects.

## License

MIT
