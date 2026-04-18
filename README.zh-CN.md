<div align="center">

# IronRDP WASM

[![English](https://img.shields.io/badge/English-README-blue)](README.md)
[![中文](https://img.shields.io/badge/中文-说明-red)](README.zh-CN.md)

[IronRDP](https://github.com/Devolutions/IronRDP) 的 WebAssembly 构建，用于浏览器端 RDP 客户端。

</div>

## 功能特性

- **RDP 连接** - 从浏览器直接连接 RDP 服务器
- **输入处理** - 键盘、鼠标和滚轮支持，使用 PS/2 Set 1 扫描码映射
- **剪贴板同步** - 本地与远程之间的文本剪贴板同步
- **文件传输** - 通过 CLIPRDR 通道上传和下载文件
  - 拖拽或文件选择器上传文件到远程桌面
  - 下载远程服务器资源管理器中复制的文件
- **WebSocket 代理** - 内置代理服务器（`rdp-proxy.js`）支持 RDCleanPath 协议

## 快速开始

```bash
npm install
npm run build
npm run example
```

在浏览器中打开 http://localhost:8080。

## 项目结构

```
ironrdp-wasm/
├── src/
│   └── lib.rs              # Rust WASM 绑定
├── pkg/                    # 构建输出（自动生成）
│   ├── rdp_client.js       # JavaScript 绑定
│   ├── rdp_client_bg.wasm  # 编译后的 WebAssembly
│   └── rdp_client.d.ts     # TypeScript 类型定义
├── example/
│   ├── index.html          # 演示 RDP 客户端界面
│   ├── style.css           # 样式文件
│   ├── server.js           # HTTP + WebSocket 代理服务器
│   └── lib/
│       ├── logger.js       # 日志和状态工具
│       ├── input.js        # 键盘/鼠标输入处理
│       ├── clipboard.js    # 剪贴板同步
│       ├── file-transfer.js # 通过 CLIPRDR 传输文件
│       ├── session.js      # 会话管理器（整合所有模块）
│       └── rdp-proxy.js    # WebSocket RDCleanPath 代理
├── Cargo.toml
└── package.json
```

## 前置要求

### Rust 工具链

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup target add wasm32-unknown-unknown
```

### wasm-pack

```bash
cargo install wasm-pack
```

### Node.js

Node.js 16+，从 [nodejs.org](https://nodejs.org/) 或通过 [nvm](https://github.com/nvm-sh/nvm) 安装。

## 构建

```bash
npm install
npm run build
```

这会执行 `wasm-pack build --target web --out-dir pkg --release`，生成：
- `pkg/rdp_client.js` - JavaScript 绑定
- `pkg/rdp_client_bg.wasm` - 编译后的 WebAssembly
- `pkg/rdp_client.d.ts` - TypeScript 类型定义

调试构建：
```bash
wasm-pack build --target web --out-dir pkg --dev
```

## 使用方法

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

### 扩展系统

IronRDP 使用扩展系统来支持可选功能：

```javascript
// 启用 CredSSP
builder.extension(new Extension('enable_credssp', true));

// 文件传输回调
builder.extension(new Extension('files_available_callback', (files, clipDataId) => {
    // 远程有文件可供下载
}));

// 剪贴板回调
builder.remoteClipboardChangedCallback((clipboardData) => {
    // 远程剪贴板已更改
});

builder.forceClipboardUpdateCallback(() => {
    // 将本地剪贴板同步到远程
});
```

## 示例应用

`example/` 文件夹包含一个完整的演示应用：
- 现代暗色主题界面，包含连接栏、画布、日志面板和文件传输面板
- 模块化 JavaScript 架构（`logger.js`、`input.js`、`clipboard.js`、`file-transfer.js`、`session.js`）
- 用于 RDCleanPath 协议的 WebSocket 代理服务器

运行示例：
```bash
cd example && npm install && cd ..
npm run build
npm run example
```

## 致谢

本项目是 [Marc-André Moreau 的 IronRDP 库](https://github.com/Devolutions/IronRDP) 的 WebAssembly 构建。所有 RDP 协议实现和核心功能均来自原始 IronRDP 项目。本项目提供构建工具链和 JavaScript 绑定，使 IronRDP 可用于 Web 项目。

## 许可证

MIT
