# Proxy Checker
Proxy Checker is a simple and efficient Python tool built using the tkinter library to check the validity of proxies. This tool allows users to load proxy lists from a file or a URL and test each proxy against a specified URL. The application supports multiple proxy types, including HTTP, HTTPS, SOCKS4, and SOCKS5.

![Free Proxy Checker and Generator](https://i.ibb.co/82fQRfm/proxy-free-checker.png)

## Features
+ Load proxies from a local file or a URL
+ Supports HTTP, HTTPS, SOCKS4, and SOCKS5 proxy types
+ Test proxies against a specified URL
+ Find valid proxies by fetching from an API
+ Display valid proxies in a text box
+ Export valid proxies to TXT or CSV format
+ Progress bar to track the proxy checking process
+ Stop button to halt the checking process

## Prerequisites
To use Proxy Checker, you need to have Python 3.6+ installed. The following Python packages are required:
+ tkinter
+ requests
+ socket
+ urllib
+ csv
+ threading
+ feedparser
+ re
+ socks

To install the required packages, run:
```python
pip install -r requirements.txt
```

## Usage
1. Run the `proxy_gui_new.py` script:
```python proxy_gui_new.py```

2. Click "Browse Proxy File" to load a list of proxies from a local file, or enter a URL in the "URL" field and click "Load Proxies from URL" to load proxies from the specified URL.

3. Select the type of proxies you want to check (HTTP, HTTPS, SOCKS4, or SOCKS5) from the "Proxy Type" dropdown menu.

4. To automatically fetch and validate proxies, check the "Find Valid Proxies" checkbox.

5. Click "Check Proxies" to start the validation process. You can click "STOP" to halt the process at any time.

6. Valid proxies will be displayed in the "Valid Proxies" text box.

7. Click "Export as TXT" or "Export as CSV" to save the list of valid proxies to a file.

## Contributing
Contributions are welcome! Please feel free to submit a Pull Request or open an Issue with any improvements or bug fixes.

## License
This project is licensed under the GNU GENERAL PUBLIC LICENSE. See the LICENSE file for details.
