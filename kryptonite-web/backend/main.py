from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import tempfile
import os
import json
import subprocess
import shutil

app = FastAPI()

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # Next.js dev server
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/analyze")
async def analyze_file(file: UploadFile = File(...)):
    # Validate file extension
    if not file.filename.lower().endswith(('.apk', '.ipa')):
        raise HTTPException(status_code=400, detail="Only .apk and .ipa files are supported")

    # Create temp directory
    with tempfile.TemporaryDirectory() as temp_dir:
        # Save uploaded file
        file_path = os.path.join(temp_dir, file.filename)
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        # Create output directory
        output_dir = os.path.join(temp_dir, "output")
        os.makedirs(output_dir, exist_ok=True)

        try:
            # Get full path to kryptonite executable
            kryptonite_path = os.path.join("kryptonite")
            
            # Run kryptonite scan
            result = subprocess.run(
                [kryptonite_path, "scan", file.filename, "--output-dir", "output", "--format", "json"],
                capture_output=True,
                text=True,
                timeout=300,  # 5 minutes timeout
                cwd=temp_dir
            )

            # Check if report was generated regardless of return code
            report_path = os.path.join(output_dir, "report.json")
            if os.path.exists(report_path):
                try:
                    with open(report_path, "r") as f:
                        report_data = json.load(f)
                    return report_data
                except json.JSONDecodeError as e:
                    raise HTTPException(status_code=500, detail=f"Invalid JSON report: {str(e)}")
            else:
                # If report not generated, check return code
                if result.returncode != 0:
                    raise HTTPException(status_code=500, detail=f"Analysis failed: stdout={result.stdout}, stderr={result.stderr}")
                else:
                    raise HTTPException(status_code=500, detail=f"Analysis completed but report not found. stdout={result.stdout}, stderr={result.stderr}")

        except subprocess.TimeoutExpired:
            raise HTTPException(status_code=408, detail="Analysis timed out")
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")