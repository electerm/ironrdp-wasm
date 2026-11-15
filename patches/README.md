# Patches applied to IronRDP

The published `ironrdp-wasm` package is built from Devolutions/IronRDP at the
revision pinned in `bin/prepare-ironrdp.js` (`IRONRDP_REV`), with the patches in
this directory applied on top.

`npm run build` does the whole thing: it downloads the pinned revision into
`.ironrdp/` (gitignored), applies the patches, and runs `wasm-pack` in a scratch
copy under `.build/` (also gitignored) whose manifest points at that checkout.
Tracked files are never rewritten, so an interrupted build leaves nothing to
clean up.

## ironrdp-web-session-responsiveness.patch

Target: `crates/ironrdp-web/src/session.rs`

Fixes the session becoming unresponsive while the remote desktop is busy (for
example an AI agent scrolling a terminal on the remote machine):

1. **Paint coalescing.** Graphics updates were blitted to the canvas as they
   arrived. `put_image_data` is a synchronous JS call, so a flood of updates
   meant a flood of JS work. Updates are now merged into one dirty rectangle and
   painted at most every 16 ms. The rectangle is read back from the framebuffer
   when the paint happens, so the merged rectangle always shows the latest
   state.
2. **Cooperative yielding.** The session loop never returned to the browser
   while frames kept arriving, so the DOM handlers that turn mouse/keyboard
   events into RDP input never ran - the session looked frozen even though the
   network was fine. The loop now yields to the event loop at least every 16
   frames, and the paint deadline uses a one-shot ticker that is only armed
   while there is something to paint (an idle session still wakes up zero
   times).
3. **Input is not starved by frames.** `futures::select!` polls its branches in
   a random order instead of always starting with the first one, so a frame that
   is always ready cannot consistently win over a pending input event. (It is
   not `biased`: that is a `tokio::select!` feature, and biasing the frame
   branch first is exactly the starvation this patch is fixing.) The periodic
   yield above bounds the worst case either way.

`enable_server_pointer` (the cursor is drawn by the frontend instead of the
server, so it moves at local input rate) used to be part of this patch; upstream
took it, so it is gone from here and the client keeps sending it as the
`enable_server_pointer` extension.

## ironrdp-web-egfx.patch

Target: `crates/ironrdp-web/Cargo.toml`, `crates/ironrdp-web/src/session.rs`

Gives the web client the Graphics Pipeline ([MS-RDPEGFX]):

1. **Channel and early capability.** The client registers the
   `Microsoft::Windows::RDS::Graphics` dynamic channel and sets
   `support_dyn_vc_gfx_protocol` in the connector config, so the server sees a
   client that supports the graphics pipeline. GNOME Remote Desktop (51.x)
   rejects every other client with "Client did not advertise support for the
   Graphics Pipeline" during the capability exchange.
2. **Compositing.** `ironrdp-session` already composites the pipeline's surfaces
   into the framebuffer and reports the damage as `GraphicsUpdate`, so the
   session loop needs no new rendering path: the channel handler is a unit struct.
   No H.264 decoder is configured, so the pipeline advertises capability sets
   without AVC and the server sends RFX, ClearCodec or uncompressed updates, all
   of which are decoded in software (no browser decoder is needed).
3. **Output resets.** A `ResetGraphics` PDU can change the framebuffer size after
   connecting. The canvas and the reported desktop size follow it, and the first
   paint after a resize covers the whole surface, since resizing a canvas clears
   it.

The `legacy_graphics` extension still turns all of this off, including the early
capability flag, for servers that expect bitmap updates only.

## Rebuilding the patch

```bash
# inside a clean checkout of IRONRDP_REV
patch -p1 < patches/ironrdp-web-session-responsiveness.patch
# ... edit crates/ironrdp-web/src/session.rs ...
diff -u --label a/crates/ironrdp-web/src/session.rs \
        --label b/crates/ironrdp-web/src/session.rs \
        old/crates/ironrdp-web/src/session.rs \
        new/crates/ironrdp-web/src/session.rs \
  > patches/ironrdp-web-session-responsiveness.patch
```
