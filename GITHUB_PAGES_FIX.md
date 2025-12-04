# GitHub Pages Deployment Guide

## ⚠️ Important: Disable Automatic Jekyll Builds

Your repository is a **React/Vite application**, not a Jekyll site. GitHub is trying to build it with Jekyll, which causes errors.

## Quick Fix: Disable GitHub Pages

### Option 1: Disable GitHub Pages Completely (Recommended if using Cloudflare Pages/Render)

1. Go to your GitHub repository: https://github.com/pallavi-git-max/XevyTalk
2. Click **Settings** → **Pages**
3. Under "Source", select **None**
4. Click **Save**

This will stop GitHub from trying to build your site.

### Option 2: Use Cloudflare Pages or Render Instead

**Cloudflare Pages** (Recommended):
- Automatically builds on every push
- Free SSL, CDN, and unlimited bandwidth
- See `CLOUDFLARE_PAGES_CONFIG.md` for setup

**Render**:
- Simple static site hosting
- See `DEPLOYMENT_GUIDE.md` for setup

## Why This Error Happened

GitHub Pages has automatic Jekyll builds enabled by default. When you push code, it tries to:
1. Find Jekyll configuration
2. Build a Jekyll site from your code
3. Look for a `docs/` folder (which doesn't exist)
4. Fail because this is a React app, not Jekyll

## The Fix

The `.nojekyll` file tells GitHub Pages to skip Jekyll processing. This file has been added to:
- Root directory: `/.nojekyll`
- Public folder: `/client/public/.nojekyll` (copied to dist during build)

## If You Want to Use GitHub Pages

If you still want to deploy to GitHub Pages, you need to:

1. **Disable automatic builds** (Settings → Pages → Source: None)
2. **Use GitHub Actions** to build and deploy manually
3. See the example workflow in `.github/workflows/deploy-github-pages.yml.example`

## Current Recommendation

✅ **Use Cloudflare Pages or Render** instead of GitHub Pages:
- Easier setup
- Better performance
- Automatic deployments
- No Jekyll issues

The `.nojekyll` file will prevent future Jekyll build errors, but you should still disable GitHub Pages in your repository settings if you're not using it.
