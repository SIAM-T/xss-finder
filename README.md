# XSS Pro - Advanced XSS Vulnerability Scanner

![Python](https://img.shields.io/badge/python-v3.6+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-windows%20%7C%20linux%20%7C%20macos-lightgrey.svg)

**XSS Pro** is a powerful, multi-threaded Cross-Site Scripting (XSS) vulnerability scanner that automatically discovers and tests web application endpoints for XSS vulnerabilities. It leverages historical web data from archive.org to find potential attack vectors.

## 🚀 Features

- **Automated URL Discovery**: Fetches URLs from Wayback Machine archives
- **Multi-threaded Scanning**: Configurable thread count for faster scanning
- **Smart URL Filtering**: Automatically filters out static files and non-parameterized URLs
- **Proxy Support**: Route requests through proxy servers
- **Real-time Progress Tracking**: Monitor scanning progress with ETA calculations
- **Colorized Output**: Easy-to-read results with color-coded status messages
- **Batch Processing**: Scan multiple domains from a file
- **Configurable Payloads**: Custom XSS payload injection
- **Results Export**: Save vulnerable URLs to organized output files

## 📋 Requirements

- Python 3.6 or higher
- Internet connection for archive.org access
- Valid target domains with proper authorization

## 🛠 Installation

1. **Clone the repository:**
```bash
git clone https://github.com/SIAM-T/xss-finder.git
cd xss-finder
```

2. **Install dependencies:**
```bash
pip install -r requirements.txt
```

3. **Run the tool:**
```bash
python xsspro.py -h
```

## 📖 Usage

### Basic Usage

**Scan a single domain:**
```bash
python xsspro.py -d example.com
```

**Scan multiple domains from a file:**
```bash
python xsspro.py -l domains.txt
```

### Advanced Usage

**Custom thread count and verbose output:**
```bash
python xsspro.py -d example.com -t 20 -v
```

**Using proxy and custom payload:**
```bash
python xsspro.py -d example.com --proxy http://127.0.0.1:8080 -p "alert(1)"
```

**Stream URLs without scanning:**
```bash
python xsspro.py -d example.com -s
```

**Custom output directory:**
```bash
python xsspro.py -d example.com -o results
```

## ⚙️ Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-d, --domain` | Target domain name | None |
| `-l, --list` | File containing list of domains | None |
| `-s, --stream` | Stream URLs to terminal without scanning | False |
| `--proxy` | Proxy server address (http://ip:port) | None |
| `-p, --placeholder` | XSS payload placeholder | `xss<>` |
| `-o, --output` | Output directory for results | `xss` |
| `-t, --threads` | Number of scanning threads | 10 |
| `-v, --verbose` | Verbose output (show all results) | False |

## 📁 Output Structure

```
xss/
├── example.com.txt          # Vulnerable URLs for example.com
├── target.org.txt           # Vulnerable URLs for target.org
└── ...
```

Each output file contains the vulnerable URLs found during the scan, one per line.

## 🔍 How It Works

1. **URL Discovery**: Queries Wayback Machine for historical URLs of the target domain
2. **URL Filtering**: Removes static files and URLs without parameters
3. **Payload Injection**: Replaces parameter values with XSS test payloads
4. **Vulnerability Testing**: Sends HTTP requests and analyzes responses
5. **Result Analysis**: Identifies reflected XSS vulnerabilities
6. **Report Generation**: Saves vulnerable URLs to organized output files

## 🎯 Example Workflow

```bash
# 1. Scan a single domain with verbose output
python xsspro.py -d vulnerable-site.com -v

# 2. Create a domains file
echo "site1.com" > targets.txt
echo "site2.com" >> targets.txt

# 3. Batch scan with custom settings
python xsspro.py -l targets.txt -t 15 -o scan_results

# 4. Review results
cat scan_results/site1.com.txt
```

## 🚨 Important Notes

### Legal and Ethical Usage
- **Only test domains you own or have explicit permission to test**
- This tool is intended for security professionals and ethical hackers
- Unauthorized testing may violate laws and regulations
- Always follow responsible disclosure practices

### Rate Limiting
- The tool implements automatic rate limiting to avoid overwhelming target servers
- Uses random user agents and exponential backoff for failed requests
- Respects server response times with built-in delays

### Accuracy
- Results may include false positives - manual verification is recommended
- The tool tests for reflected XSS only
- Complex XSS scenarios may require manual testing

## 🛡️ Security Considerations

- **Use responsibly**: Only scan domains you own or have permission to test
- **Network monitoring**: Scanning activities may be logged by target systems
- **Proxy usage**: Consider using proxy servers for additional privacy
- **Legal compliance**: Ensure compliance with local laws and regulations

## 🔧 Customization

### Custom Payloads
Modify the default payload by using the `-p` option:
```bash
python xsspro.py -d example.com -p '<script>alert("XSS")</script>'
```

### File Extensions
The tool automatically filters out common static file extensions. To modify the list, edit the `HARDCODED_EXTENSIONS` constant in the source code.

### User Agents
Random user agents are used to avoid detection. Additional user agents can be added to the `USER_AGENTS` list in the source code.

## 📊 Performance Tips

1. **Optimize thread count**: Start with 10 threads and adjust based on your system and network
2. **Use proxy for large scans**: Distribute load across multiple proxy servers
3. **Monitor progress**: Press spacebar during scanning to see real-time progress
4. **Batch processing**: Process multiple domains efficiently using the list option

## 🐛 Troubleshooting

### Common Issues

**"No URLs with parameters to scan"**
- The target domain may not have archived URLs with query parameters
- Try checking if the domain exists in Wayback Machine manually

**Connection timeouts**
- Reduce thread count (`-t` option)
- Check internet connection and proxy settings
- Verify target domain accessibility

**Permission errors**
- Ensure write permissions in the output directory
- Run with appropriate user privileges

### Debug Mode
Use verbose mode (`-v`) to see detailed scanning progress and identify issues.

## 📈 Performance Metrics

- **Scanning Speed**: ~100-500 URLs per minute (depending on target response times)
- **Memory Usage**: ~50-200MB (scales with thread count)
- **Network Bandwidth**: ~1-10 Mbps (varies with payload size and frequency)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 📞 Support

- **Issues**: Report bugs and request features via [GitHub Issues](https://github.com/SIAM-T/xss-finder/issues)
- **Documentation**: Check this README and inline code comments
- **Community**: Join discussions in the [GitHub repository](https://github.com/SIAM-T/xss-finder)

## ⚠️ Disclaimer

This tool is provided for educational and security testing purposes only. Users are responsible for ensuring they have proper authorization before testing any systems. The authors are not responsible for any misuse or damage caused by this tool.

---

**Happy Ethical Hacking! 🔒** 
