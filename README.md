# IronRDP WASM

This project compiles [Marc-André Moreau's IronRDP](https://github.com/Devolutions/IronRDP) Web client to WebAssembly (WASM) for use in web projects. It provides a JavaScript module that can be imported into web applications to enable RDP connectivity.

## What it is

- **ironrdp-wasm** is a WebAssembly build of the [IronRDP](https://github.com/Devolutions/IronRDP) library, specifically the `ironrdp-web` crate created by Marc-André Moreau.
- This package simply compiles the existing IronRDP Rust code to WebAssembly - **all credit for the RDP implementation goes to the original IronRDP project**.
- It allows web applications to connect to RDP servers directly from the browser.
- Combined with `lib/rdp-proxy.js` (now in the example folder), it provides a complete RDP client solution for web.

## Installation

```bash
npm install ironrdp-wasm
```

## Usage

```javascript
import { init, SessionBuilder } from 'ironrdp-wasm';

// Initialize the WASM module
await init();

// Create a session
const session = new SessionBuilder()
  .withUsername('user')
  .withPassword('pass')
  .withDomain('domain')
  .withHost('rdp-server.example.com')
  .build();

// Connect
await session.connect();
```

## Prerequisites

Before building this project, ensure you have the following installed:

### Rust Toolchain
Install Rust using [rustup](https://rustup.rs/):
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Add the WebAssembly target:
```bash
rustup target add wasm32-unknown-unknown
```

### wasm-pack
Install `wasm-pack` for building Rust-generated WebAssembly packages:
```bash
cargo install wasm-pack
```

### Node.js and npm
Install Node.js (version 16 or later) from [nodejs.org](https://nodejs.org/) or using a version manager like [nvm](https://github.com/nvm-sh/nvm).

## Building

To build the WASM module from source:

1. **Clone the repository:**
   ```bash
   git clone https://github.com/electerm/ironrdp-wasm.git
   cd ironrdp-wasm
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Build the WASM module:**
   ```bash
   npm run build
   ```

This command runs `wasm-pack build --target web --out-dir pkg --release`, which:
- Compiles the Rust code in `src/lib.rs` to WebAssembly
- Generates JavaScript bindings in the `pkg/` directory
- Optimizes the WASM binary for production

The build output will be in the `pkg/` folder, containing:
- `rdp_client.js` - JavaScript bindings
- `rdp_client_bg.wasm` - The compiled WebAssembly module
- `rdp_client.d.ts` - TypeScript definitions

## Development

For development builds (with debug symbols):
```bash
wasm-pack build --target web --out-dir pkg --dev
```

To clean the build:
```bash
rm -rf pkg/
```

## Example

See the `example/` folder for a complete demo application that includes:
- A web-based RDP client UI (`index.html`)
- A WebSocket proxy server (`server.js`) for handling RDP connections
- Proxy utilities (`lib/rdp-proxy.js`)

To run the example:

1. **Install example dependencies:**
   ```bash
   cd example
   npm install
   cd ..
   ```

2. **Build the WASM module (if not already built):**
   ```bash
   npm run build
   ```

3. **Start the example server:**
   ```bash
   npm run example
   ```

Then open http://localhost:8080 in your browser.

## API

The module exports all functions and classes from the IronRDP Web API. Refer to the IronRDP documentation for detailed API reference.

## Credits

This package is a WebAssembly compilation of [Marc-André Moreau's IronRDP library](https://github.com/Devolutions/IronRDP). All RDP protocol implementation and core functionality is from the original IronRDP project. This package simply provides the build tooling and JavaScript bindings to make IronRDP available for web projects.

## License

MIT