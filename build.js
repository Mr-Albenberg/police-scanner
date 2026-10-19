// Build step: emit an obfuscated, minified copy of the site into dist/.
//
// The repo keeps index.html / sw.js as the readable SOURCE (what we edit); this
// script produces the unreadable version that actually gets served, so "View
// source" / devtools show a single minified line instead of clean, commented
// code. (Client code can never be fully hidden — the browser must run it — this
// just raises the bar against casual copying.)
//
// Top-level names are intentionally NOT mangled: some Web Workers are built from
// a function's source string, and renaming across that boundary would break
// them. Everything inside functions is mangled and all comments/whitespace are
// stripped, which is what makes it unreadable.
const fs = require('fs');
const path = require('path');
const { minify } = require('html-minifier-terser');
const { minify: terser } = require('terser');

const OUT = 'dist';
const ASSETS = ['logo.png', 'favicon-32.png', 'manifest.webmanifest', 'streets.json'];

const JS_OPTS = {
  compress: { drop_console: false, passes: 2 },
  mangle: { toplevel: false }, // keep globals; mangle locals only (safe for the string-built workers)
  format: { comments: false },
};

async function run() {
  fs.rmSync(OUT, { recursive: true, force: true });
  fs.mkdirSync(OUT, { recursive: true });

  const html = fs.readFileSync('index.html', 'utf8');
  const min = await minify(html, {
    collapseWhitespace: true,
    removeComments: true,
    removeRedundantAttributes: false,
    minifyCSS: true,
    caseSensitive: true,       // preserve inline SVG attribute casing
    keepClosingSlash: true,    // keep self-closing SVG tags valid
    minifyJS: JS_OPTS,
  });
  fs.writeFileSync(path.join(OUT, 'index.html'), min);

  const sw = fs.readFileSync('sw.js', 'utf8');
  const swMin = await terser(sw, JS_OPTS);
  fs.writeFileSync(path.join(OUT, 'sw.js'), swMin.code || sw);

  for (const a of ASSETS) {
    if (fs.existsSync(a)) fs.copyFileSync(a, path.join(OUT, a));
  }

  const inSize = Buffer.byteLength(html);
  const outSize = fs.statSync(path.join(OUT, 'index.html')).size;
  console.log(`dist/ built — index.html ${(inSize / 1024).toFixed(0)}KB -> ${(outSize / 1024).toFixed(0)}KB`);
}

run().catch((e) => { console.error(e); process.exit(1); });
