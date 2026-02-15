# Kryptonite UI

Advanced mobile security analysis tool - Vite + React frontend

## Features

- 🔒 Mobile app security analysis (APK & IPA)
- 🎨 Modern UI with Tailwind CSS
- ⚡ Fast build with Vite
- 📱 Responsive design

## Development

```bash
# Install dependencies
npm install

# Start dev server (runs on http://localhost:3000)
npm run dev

# Build for production
npm run build

# Preview production build
npm run preview
```

## Deployment on Vercel

### Option 1: Deploy from Repository Root

If deploying the monorepo, configure Vercel project settings:

1. Go to Project Settings → General
2. Set **Root Directory** to: `kryptonite-ui`
3. Build Command: `npm run build` (auto-detected)
4. Output Directory: `dist` (auto-detected)
5. Install Command: `npm install` (auto-detected)

### Option 2: Deploy kryptonite-ui Separately

Deploy just the `kryptonite-ui` folder as a standalone project:

```bash
cd kryptonite-ui
vercel
```

The `vercel.json` config ensures:
- SPA routing works correctly (all routes redirect to index.html)
- Proper build configuration
- Correct output directory

## Project Structure

```
kryptonite-ui/
├── public/           # Static assets
├── src/
│   ├── App.tsx      # Main application component
│   ├── main.tsx     # React entry point
│   └── index.css    # Global styles with Tailwind
├── index.html       # HTML template
├── vite.config.ts   # Vite configuration
├── vercel.json      # Vercel deployment config
└── package.json     # Dependencies and scripts
```

## Environment Variables

If you need to change the API endpoint, update the fetch URL in `src/App.tsx`:

```typescript
const response = await fetch("YOUR_API_URL/analyze", {
  method: "POST",
  body: formData,
});
```

## Tech Stack

- **React 18** - UI library
- **TypeScript** - Type safety
- **Vite** - Build tool
- **Tailwind CSS** - Styling
- **Vercel** - Deployment platform
