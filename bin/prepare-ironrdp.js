/**
 * Materialize the IronRDP checkout the wasm package is built from.
 *
 * `ironrdp-web` has to be patched (see ../patches) and a Cargo dependency on a
 * patched git checkout is not something npm can express, so the build downloads
 * the pinned revision, applies the patches and points Cargo at the local copy
 * for the duration of the build (see build.js).
 *
 * The checkout is recreated from scratch whenever the pinned revision or any
 * patch changes, which keeps the whole thing deterministic - there is no
 * "is this patch already applied?" guesswork. Delete `.ironrdp/` to force it.
 */
import { execSync } from 'child_process'
import { createHash } from 'crypto'
import {
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync
} from 'fs'
import { dirname, join } from 'path'
import { fileURLToPath } from 'url'

// Pinned upstream revision. Bump this together with the patches.
export const IRONRDP_REV = 'd0e18e3693f313e83c769fb37fa991965d2a39d3'

const TARBALL_URL =
  `https://codeload.github.com/Devolutions/IronRDP/tar.gz/${IRONRDP_REV}`

const here = dirname(fileURLToPath(import.meta.url))
export const ROOT = join(here, '..')
export const CHECKOUT = join(ROOT, '.ironrdp')

const PATCHES = [
  'patches/ironrdp-web-session-responsiveness.patch'
]

const STAMP = join(CHECKOUT, '.build-stamp')

function sh (cmd, cwd) {
  execSync(cmd, { stdio: 'inherit', cwd })
}

function fingerprint () {
  const hash = createHash('sha256').update(IRONRDP_REV)
  for (const rel of PATCHES) {
    hash.update(readFileSync(join(ROOT, rel)))
  }
  return hash.digest('hex')
}

export function prepareIronRdp () {
  const want = fingerprint()

  if (existsSync(STAMP) && readFileSync(STAMP, 'utf8').trim() === want) {
    console.log(`[ironrdp] checkout up to date (${IRONRDP_REV.slice(0, 12)})`)
    return CHECKOUT
  }

  console.log(`[ironrdp] fetching ${IRONRDP_REV}`)
  rmSync(CHECKOUT, { recursive: true, force: true })
  mkdirSync(CHECKOUT, { recursive: true })
  sh(`curl -sSL "${TARBALL_URL}" | tar xz -C "${CHECKOUT}" --strip-components=1`, ROOT)

  for (const rel of PATCHES) {
    console.log(`[ironrdp] applying ${rel}`)
    // --batch: never stop to ask a question (a prompt would hang a CI build)
    // -N: a patch that does not apply cleanly is an error, not a .rej file
    sh(`patch -p1 --batch -N < "${join(ROOT, rel)}"`, CHECKOUT)
  }

  writeFileSync(STAMP, `${want}\n`)
  return CHECKOUT
}

if (process.argv[1] && process.argv[1].endsWith('prepare-ironrdp.js')) {
  console.log(prepareIronRdp())
}
