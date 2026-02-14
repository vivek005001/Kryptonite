# Kryptonite Web

A web interface for the Kryptonite mobile static analysis security tool.

## Features

- Upload APK or IPA files for analysis
- Real-time security scanning using Kryptonite
- Interactive results display with severity breakdown
- Detailed findings with evidence and remediation guidance

## Setup

### Prerequisites

- Node.js 18+
- Python 3.10+
- Kryptonite CLI installed (from parent directory)

### Installation

1. Install frontend dependencies:

```bash
cd kryptonite-web
npm install
```

2. The backend dependencies are already set up in `backend/` with a virtual environment.

### Running the Application

1. Start the backend server:

```bash
cd kryptonite-web/backend
source venv/bin/activate
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

2. In a new terminal, start the frontend:

```bash
cd kryptonite-web
npm run dev
```

3. Open http://localhost:3000 in your browser.

## API

### POST /analyze

Upload a mobile app file for analysis.

**Request:**

- Content-Type: multipart/form-data
- Body: file (APK or IPA file)

**Response:**

- JSON report data from Kryptonite analysis

## Development

- Frontend: Next.js with TypeScript and Tailwind CSS
- Backend: FastAPI with CORS support
- Analysis: Uses the Kryptonite CLI tool
