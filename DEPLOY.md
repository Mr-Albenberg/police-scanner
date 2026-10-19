# Deploying (private source + obfuscated site)

The site is a static page. We keep **`index.html` / `sw.js` as the readable
source** (edit these), and a build step emits an **obfuscated `dist/`** that
actually gets served, so "View source" / devtools show one minified line
instead of clean, commented code.

> Reality check: client code can never be fully hidden — the browser has to
> download and run it, so a determined person can still read the minified
> output. This raises the bar against casual copying; it is not encryption.

## Build locally

```bash
npm install      # once
npm run build    # writes dist/
```

`dist/` and `node_modules/` are git-ignored — Vercel rebuilds `dist/` on each
deploy, so you never commit the obfuscated output.

## Make the repo private + deploy on Vercel

GitHub Pages won't serve a **private** repo on the free plan, so move hosting to
Vercel (free, and it builds the obfuscated `dist/` for you):

1. **Push these build files** (already done): `package.json`, `package-lock.json`,
   `build.js`, `vercel.json`.
2. **GitHub → repo → Settings → General → Danger Zone → Change visibility →
   Private.** (Optionally turn off GitHub Pages under Settings → Pages so the
   public `*.github.io` copy stops serving the readable source.)
3. **Vercel → Add New → Project → Import** this GitHub repo (authorize Vercel to
   read the private repo). Vercel reads `vercel.json`: build `npm run build`,
   serve `dist/`. Click **Deploy**.
4. Point your domain at the Vercel deployment (Vercel → Project → Settings →
   Domains) if you use a custom domain.

After that, every `git push` to `main` triggers a Vercel build that serves the
obfuscated `dist/`, and the source repo is private.

## Note

The Cloudflare Worker (`relay/`) is deployed separately with `wrangler deploy`
and is unaffected by any of this. All secrets live as Worker secrets — nothing
sensitive is in the client.
