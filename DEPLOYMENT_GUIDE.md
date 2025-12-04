# Quick Deployment Guide for Render

## ✅ What's Been Fixed
The 404 error on page refresh has been fixed by adding a `_redirects` file that tells the server to serve `index.html` for all routes.

## 🚀 Deploy to Render (Static Site)

### Step 1: Push Changes to Git
```bash
git add .
git commit -m "Fix 404 error on page refresh - add _redirects file"
git push origin main
```

### Step 2: Deploy on Render

#### Option A: Using Render Dashboard (Recommended)
1. Go to [Render Dashboard](https://dashboard.render.com/)
2. Click "New +" → "Static Site"
3. Connect your GitHub/GitLab repository
4. Configure:
   - **Name**: `xevytalk-client`
   - **Branch**: `main` (or your default branch)
   - **Build Command**: `cd client && npm install && npm run build`
   - **Publish Directory**: `client/dist`
5. Click "Create Static Site"

#### Option B: Using render.yaml (Blueprint)
1. Go to [Render Dashboard](https://dashboard.render.com/)
2. Click "New +" → "Blueprint"
3. Connect your repository
4. Render will automatically detect `render.yaml` and set up both services

### Step 3: Set Environment Variables
In your Render dashboard for the client service:
1. Go to "Environment" tab
2. Add environment variable:
   - **Key**: `VITE_API_URL`
   - **Value**: `https://xevytalk-server.onrender.com` (your backend URL)

### Step 4: Verify Deployment
1. Wait for build to complete (usually 2-5 minutes)
2. Visit your deployed URL (e.g., `https://xevytalk-client.onrender.com`)
3. Navigate to `/chat` route
4. **Refresh the page** - it should now work without 404 error! ✅

## 🧪 Test Locally Before Deploying

```bash
# Build the production version
cd client
npm run build

# Preview the production build
npm run preview

# Open browser and test:
# 1. Go to http://localhost:4173
# 2. Navigate to /chat
# 3. Refresh the page - should work!
```

## 📋 Checklist

- [x] `_redirects` file created in `client/public/`
- [x] `render.yaml` configuration created
- [x] Build tested locally
- [ ] Changes committed to git
- [ ] Changes pushed to GitHub/GitLab
- [ ] Deployed to Render
- [ ] Environment variables set
- [ ] Tested page refresh on deployed site

## 🔧 Troubleshooting

### Still seeing 404 after deployment?
1. Check Render logs for build errors
2. Verify `_redirects` file is in `client/dist/` after build
3. Make sure "Publish Directory" is set to `client/dist`
4. Clear browser cache and try again

### Build failing on Render?
1. Check that `package.json` has all dependencies
2. Verify build command is correct: `cd client && npm install && npm run build`
3. Check Render logs for specific error messages

### API calls not working?
1. Make sure `VITE_API_URL` environment variable is set
2. Verify backend server is running
3. Check CORS settings on backend

## 📚 Additional Resources
- [Render Static Site Docs](https://render.com/docs/static-sites)
- [Vite Production Build](https://vitejs.dev/guide/build.html)
- [React Router with SPAs](https://reactrouter.com/en/main/start/faq#what-is-a-spa)
