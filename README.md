# File Cleaner

Removes trailing **junk bytes** appended after the last valid chunk of a
media/image/archive file. Such bytes come from bad downloads or external
tampering and break some players. Supported: `mp4/mov`, `wmv`, `mkv`, `jpeg`,
`png`, `zip`, `pdf`, `avi`.

## Monorepo layout

```
packages/
  core/            Pure TypeScript cleaning logic (no DOM, no deps)
  web/             Vite browser app - 100% client-side, nothing uploaded
  desktop-legacy/  Original Python GUI + Perl script (reference)
```

## Browser app

Files are read, stripped and re-downloaded entirely in the browser. No server,
no upload. Drag & drop one or more files, then download the cleaned copies.

```bash
npm install        # installs workspace deps
npm run build      # builds core, then the static web bundle (packages/web/dist)
npm run dev        # local dev server (Vite)
npm run preview    # preview the production build
```

The build is fully static (`base: "./"`), so `packages/web/dist` can be hosted
on GitHub Pages, Netlify, any static host.

## Core library

`@file-cleaner/core` is framework-free and reusable:

```ts
import { cleanFile } from "@file-cleaner/core";

const result = cleanFile(new Uint8Array(await file.arrayBuffer()));
if (result.cleaned) {
  // result.data  -> cleaned bytes
  // result.junk  -> removed trailing bytes (backup)
}
```

```bash
npm test           # core unit tests (node:test)
```

## Legacy desktop

See [packages/desktop-legacy](packages/desktop-legacy/) for the original Python
Tkinter GUI and the `videocleaner.pl` Perl script the logic was ported from.
