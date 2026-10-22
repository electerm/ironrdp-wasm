import {
  cpSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  unlinkSync,
  writeFileSync
} from 'fs'
import { join } from 'path'
import { execSync } from 'child_process'
import { prepareIronRdp, ROOT } from './prepare-ironrdp.js'

// Scratch build directory. The crate is built from a copy here instead of from
// the repo root so that the tracked Cargo.toml never has to be rewritten: an
// interrupted build (Ctrl-C, crash) cannot leave the working tree pointing at a
// local checkout that no longer exists.
const BUILD_DIR = join(ROOT, '.build')
const PKG_DIR = join(ROOT, 'pkg')

function clearDirectory (dirPath) {
  if (!existsSync(dirPath)) return
  readdirSync(dirPath).forEach((file) => {
    const filePath = join(dirPath, file)
    if (lstatSync(filePath).isDirectory()) {
      rmSync(filePath, { recursive: true, force: true })
    } else {
      unlinkSync(filePath)
    }
  })
}

// Clear the pkg folder
clearDirectory(PKG_DIR)

// Fetch + patch IronRDP, then build against that checkout instead of the
// published git dependency.
const checkout = prepareIronRdp()

// Only the manifest and the sources are rewritten; `target/` is kept so that a
// rebuild after a source change stays incremental (a cold build of the whole
// dependency tree takes minutes).
mkdirSync(BUILD_DIR, { recursive: true })

const manifest = readFileSync(join(ROOT, 'Cargo.toml'), 'utf8')
const patchedManifest = manifest.replace(
  /^ironrdp-web = .*$/m,
  'ironrdp-web = { path = "../.ironrdp/crates/ironrdp-web" }'
)

if (patchedManifest === manifest) {
  throw new Error('could not point the build manifest at the patched IronRDP checkout')
}

// `[workspace]` stops cargo from treating the copy as part of an enclosing
// workspace (and keeps its lockfile local to the build).
writeFileSync(join(BUILD_DIR, 'Cargo.toml'), `${patchedManifest}\n\n[workspace]\n`)

rmSync(join(BUILD_DIR, 'src'), { recursive: true, force: true })
cpSync(join(ROOT, 'src'), join(BUILD_DIR, 'src'), { recursive: true })

// Run wasm-pack build
execSync('wasm-pack build --target web --out-dir pkg --release', {
  stdio: 'inherit',
  cwd: BUILD_DIR
})

// wasm-pack writes the package into the build directory; the published
// artifact lives at the repo root.
rmSync(PKG_DIR, { recursive: true, force: true })
renameSync(join(BUILD_DIR, 'pkg'), PKG_DIR)

// Remove the files wasm-pack generates for its own publishing flow. Which of
// them exist depends on the wasm-pack version, so missing ones are fine.
for (const file of ['.gitignore', 'package.json', 'README.md']) {
  rmSync(join(PKG_DIR, file), { force: true })
}

console.log(`\nbuilt against IronRDP checkout: ${checkout}`)
