# The Ultimate Cybersecurity Toolkit

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Build Status](https://img.shields.io/badge/build-passing-brightgreen)

Developed by Mohammed Muhaimin

A comprehensive suite of **54 cybersecurity tools** designed for security enthusiasts, penetration testers, and developers. This toolkit provides a **command-line interface (CLI)** to perform tasks ranging from cryptography and network security to web and file system analysis. Built with Python, it’s cross-platform and easy to use.

> **⚠️ Ethical Use Warning**: These tools are for educational and authorized testing only. Unauthorized use on systems you don’t own or have permission to test is illegal and unethical.

A web app version is available at [https://cyber-shell-chi.vercel.app/dashboard](https://cyber-shell-chi.vercel.app/dashboard), but **most tools cannot run on the web app**. For better outputs, use the CLI Python script described below.

## Features

- **54 Tools**: Organized into categories:
  - **Cryptography & Encryption**: Caesar Cipher, Base64, SHA-256, XOR Cipher, etc.
  - **Password Security**: Password strength checker, bcrypt hashing, random password generator.
  - **Network Security**: Port scanner, packet sniffer, DNS resolver, SSL checker.
  - **Web Security**: SQL injection scanner, XSS sanitizer, security headers checker.
  - **File System Security**: Malware hash checker, keylogger detector, file encryption.
  - **System Security**: Password breach checker, log analyzer, steganography.
- **Command-Line Interface**: Text-based, ideal for scripting and terminal users.
- **Cross-Platform**: Runs on Windows, macOS, and Linux.
- **Logging**: Tracks operations and errors in a log file.
- **Unit Tests**: Includes basic tests for core functionality.

## Installation

### Prerequisites
- **Python 3.8+**
- Required libraries:
  ```bash
  pip install requests beautifulsoup4 bcrypt python-zxcvbn scapy dnspython psutil Pillow exifread cryptography
  ```
- Some tools (e.g., `packet_sniffer`, `list_connected_devices`) require **root/admin privileges**.

### Steps
1. **Clone the Repository**:
   ```bash
   git clone https://github.com/yourusername/the-ultimate-cybersecurity-toolkit.git
   cd the-ultimate-cybersecurity-toolkit
   ```

2. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the Toolkit**:
   ```bash
   python cybersecurity_toolkit.py
   ```

## Usage

1. Run the script:
   ```bash
   python cybersecurity_toolkit.py
   ```
2. Select a tool by entering its number (1–54).
3. Follow prompts to input parameters (e.g., text, file paths).
4. View results in the terminal.
5. Use `0` to exit or `99` for a quick test of select tools.

**Example: XSS Sanitizer**
```bash
Enter tool number: 23
Enter string to sanitize: <script>alert('test')</script>
RESULTS: <script>alert('test')</script>
```

## Tools List
| Category                | Example Tools                              |
|-------------------------|--------------------------------------------|
| Cryptography            | Caesar Cipher, Base64, SHA-256            |
| Password Security       | Password Strength, bcrypt Hash            |
| Network Security        | Port Scanner, DNS Resolver, SSL Checker   |
| Web Security            | SQL Injection Scanner, XSS Sanitizer      |
| File System Security    | Malware Checker, File Encryptor           |
| System Security         | Password Breach Checker, Log Analyzer     |

> **Note**: See the source code or run the program for the full list of 54 tools.

## Ethical Considerations
- **Authorized Use Only**: Tools like `port_scanner` and `sql_injection_scanner` are for testing systems you own or have explicit permission to analyze.
- **Warnings**: The CLI includes prompts to confirm usage of sensitive tools.
- **Compliance**: Ensure compliance with local laws and regulations.

## Contributing
Contributions are welcome! To contribute:
1. Fork the repository.
2. Create a feature branch (`git checkout -b feature-name`).
3. Commit changes (`git commit -m 'Add feature'`).
4. Push to the branch (`git push origin feature-name`).
5. Open a pull request.

Please follow the [Code of Conduct](CODE_OF_CONDUCT.md) and include tests for new features.

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgments
- Built with Python and open-source libraries.
- Inspired by the need for accessible cybersecurity tools.
- Thanks to contributors and the open-source community.

## Contact
For issues or suggestions, open an issue on GitHub or contact [am.muhaimin25@gmail.com](mailto:am.muhaimin25@gmail.com).

---

**Happy Hacking (Ethically)!**
