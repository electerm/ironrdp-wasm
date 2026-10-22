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
4. **`enable_server_pointer` extension.** The cursor is drawn by the frontend
   instead of the server. A server-side pointer can only move as fast as the
   graphics pipeline delivers pointer updates, which is the first thing that
   looks frozen under load. Pass `false` from the client to enable.

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
