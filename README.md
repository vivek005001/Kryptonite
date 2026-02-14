# Kryptonite

🛡️ **Kryptonite** — Mobile Static Analysis Security Tool for iOS and Android

[![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)](https://github.com/your-repo/kryptonite)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)

A powerful static analysis tool designed to identify security vulnerabilities in mobile applications. Kryptonite supports both iOS (IPA) and Android (APK) applications, providing comprehensive security assessments through multiple specialized analyzers.

## Features

- **Cross-Platform Support**: Analyze both iOS (.ipa) and Android (.apk) applications
- **Comprehensive Analysis**: 13+ specialized security analyzers covering various attack vectors
- **Multiple Output Formats**: Generate reports in JSON and HTML formats
- **Fast & Efficient**: Optimized for quick analysis of large applications
- **CLI Interface**: Simple command-line interface with flexible options
- **Web Interface**: User-friendly web application for uploading and analyzing mobile apps
- **Detailed Findings**: Rich security findings with severity levels and remediation guidance

## Security Analyzers

### Shared Analyzers (iOS & Android)

- **Hardcoded Secrets**: Detects API keys, passwords, and other sensitive data
- **Weak Cryptography**: Identifies insecure cryptographic implementations
- **Logging & Debug Code**: Finds debug information and logging vulnerabilities

### iOS-Specific Analyzers

- **Transport Security**: Analyzes network communication security
- **Permissions Audit**: Reviews app permissions and entitlements
- **Binary Protections**: Checks for binary hardening and protection mechanisms
- **Data Storage**: Examines local data storage security
- **URL Schemes**: Validates custom URL scheme implementations

### Android-Specific Analyzers

- **Manifest Security**: Audits Android manifest for security configurations
- **Permissions Audit**: Reviews Android permission declarations
- **Binary Protections**: Analyzes DEX and native library protections
- **Transport Security**: Checks network security configurations
- **Data Storage**: Reviews Android data storage implementations
- **Component Exposure**: Identifies exposed app components

## Installation

### Prerequisites

- Python 3.10 or higher
- Node.js 18+ (for web interface)
- For iOS analysis: Basic iOS development tools (optional)
- For Android analysis: Basic Android SDK tools (optional)

### Install from Source

```bash
git clone https://github.com/your-repo/kryptonite.git
cd kryptonite
pip install -r requirements.txt
pip install -e .

# Optional: Set up web interface
cd kryptonite-web
npm install
cd backend
python -m venv venv
source venv/bin/activate
pip install fastapi uvicorn python-multipart
pip install -e ../..
```

### Install from PyPI (when available)

```bash
pip install kryptonite
```

## Usage

### Basic Scan

```bash
kryptonite scan path/to/app.ipa
kryptonite scan path/to/app.apk
```

### Advanced Options

```bash
# Specify output directory
kryptonite scan app.ipa --output-dir ./reports

# Choose output format
kryptonite scan app.apk --format json    # JSON only
kryptonite scan app.apk --format html    # HTML only
kryptonite scan app.apk --format all     # Both JSON and HTML (default)

# Get help
kryptonite --help
kryptonite scan --help
```

### Example Output

```
🛡️  Kryptonite — Mobile Static Analysis Security Tool

📱 Platform detected: iOS
⏳ Extracting MyApp.ipa...
✅ Extracted 1247 files from MyApp (com.example.myapp) in 2.3s
✅ Binary: MyApp | 45632 strings extracted

⏳ Running Hardcoded Secrets analyzer...
✅ Hardcoded Secrets: 3 finding(s)
⏳ Running Weak Cryptography analyzer...
✅ Weak Cryptography: 1 finding(s)
...

⏳ Generating reports...
✅ JSON report → ./kryptonite-report/report.json
✅ HTML report → ./kryptonite-report/report.html

╔══════════════════════════════════════╗
║  Scan Complete — 12 findings        ║
╠══════════════════════════════════════╣
║  🔴 Critical:   1                   ║
║  🟠 High:       3                   ║
║  🟡 Medium:     5                   ║
║  🟢 Low:        2                   ║
║  🔵 Info:       1                   ║
╚══════════════════════════════════════╝
```

## Output Formats

### JSON Report

Structured JSON output containing:

- App metadata (bundle ID, version, platform info)
- Detailed findings with severity, description, and location
- Analysis timestamps and summary statistics

### HTML Report

Interactive web-based report featuring:

- Executive summary with severity breakdown
- Detailed findings table with filtering and search
- Code snippets and remediation guidance
- Responsive design for easy viewing

## Web Interface

Kryptonite includes a modern web application for easy mobile app analysis without command-line usage.

### Features

- **File Upload**: Drag-and-drop interface for APK and IPA files
- **Real-time Analysis**: Live progress updates during scanning
- **Interactive Reports**: Filterable findings with severity levels
- **Risk Assessment**: Overall risk score and security recommendations
- **Evidence Display**: Code snippets and file locations for each finding

### Running the Web App

1. **Install Dependencies**:

   ```bash
   cd kryptonite-web
   npm install
   ```

2. **Start the Backend**:

   ```bash
   cd kryptonite-web/backend
   source venv/bin/activate
   uvicorn main:app --host 0.0.0.0 --port 8000
   ```

3. **Start the Frontend** (in a new terminal):

   ```bash
   cd kryptonite-web
   npm run dev
   ```

4. **Access**: Open http://localhost:3000 in your browser

### Web API

The web interface uses a REST API for analysis:

- **POST /analyze**: Upload and analyze a mobile app file
  - Accepts: `multipart/form-data` with `file` field
  - Returns: JSON report with findings and metadata

## Development

### Project Structure

```
kryptonite/
├── __init__.py
├── __main__.py
├── cli.py
├── analyzers/
│   ├── __init__.py
│   ├── crypto_analyzer.py
│   ├── logging_analyzer.py
│   ├── secrets_analyzer.py
│   ├── android/
│   │   ├── __init__.py
│   │   ├── binary_analyzer.py
│   │   ├── component_analyzer.py
│   │   ├── data_storage_analyzer.py
│   │   ├── manifest_analyzer.py
│   │   ├── permissions_analyzer.py
│   │   └── transport_analyzer.py
│   └── ios/
│       ├── __init__.py
│       ├── binary_analyzer.py
│       ├── data_storage_analyzer.py
│       ├── permissions_analyzer.py
│       ├── transport_analyzer.py
│       └── url_scheme_analyzer.py
├── core/
│   ├── __init__.py
│   ├── apk_parser.py
│   ├── finding.py
│   ├── ipa_parser.py
│   └── owasp.py
└── reports/
    ├── __init__.py
    ├── report_generator.py
    └── template.html
kryptonite-web/
├── backend/
│   ├── main.py
│   └── venv/
├── src/
│   └── app/
│       ├── layout.tsx
│       ├── page.tsx
│       └── globals.css
├── package.json
├── tailwind.config.ts
├── next.config.ts
└── README.md
tests/
├── __init__.py
├── conftest.py
└── test_*.py
```

### Running Tests

```bash
# Run all tests
python -m pytest tests/

# Run with coverage
python -m pytest --cov=kryptonite tests/
```

### Building Documentation

```bash
# Generate documentation (if applicable)
# Add documentation build commands here
```

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup

```bash
git clone https://github.com/your-repo/kryptonite.git
cd kryptonite
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
pip install -e .
```

## Security Notice

Kryptonite is designed for security research and educational purposes. Always ensure you have proper authorization before analyzing applications. The tool should not be used for malicious purposes.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built with ❤️ for the mobile security community
- Inspired by the need for accessible mobile app security analysis
- Thanks to all contributors and the open-source community

## Support

- 📧 Email: support@kryptonite.dev
- 🐛 Issues: [GitHub Issues](https://github.com/your-repo/kryptonite/issues)
- 📖 Documentation: [Wiki](https://github.com/your-repo/kryptonite/wiki)

---

**Kryptonite** - Making mobile app security analysis accessible to everyone.</content>
