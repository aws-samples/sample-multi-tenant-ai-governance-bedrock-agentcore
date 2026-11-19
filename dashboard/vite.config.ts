import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// base '/' — root-absolute, NOT './'. Tested live, and relative broke deep links
// in a way that looks like a build problem rather than a config one:
//
//   1. /reviews returns index.html (the SPA rewrite in the CloudFront construct)
//   2. its relative src resolves to /reviews/assets/index-xxx.js
//   3. that 404s in S3, so the SAME rewrite returns index.html again — 200 OK
//   4. the browser refuses to execute text/html as a module
//
// Net result: a blank page with a console error and a 200 on every request, so
// nothing in the network tab looks wrong. Root-absolute paths resolve identically
// from any depth, which is what a single-page app on CloudFront needs.
export default defineConfig({
  plugins: [react()],
  base: '/',
  build: { outDir: 'dist', sourcemap: false },
})
