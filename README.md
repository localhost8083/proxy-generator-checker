
# Proxy Checker
Proxy Checker is a simple and efficient Python tool built using the tkinter library to check the validity of proxies. This tool allows users to load proxy lists from a file or a URL and test each proxy against a specified URL. The application supports multiple proxy types, including HTTP, HTTPS, SOCKS4, and SOCKS5.

![Free Proxy Checker and Generator](https://i.ibb.co/82fQRfm/proxy-free-checker.png)

![Free Proxy Checker](https://i.ibb.co/P18CNBk/1.gif) ![Free Proxy Checker](https://i.ibb.co/VtPphts/2.gif)

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


## Usage

1. Clone this repository to your local machine using the following command:

```python
git clone https://github.com/localhost8083/proxy-generator-checker.git
```

2. Navigate to the project directory:

```python
cd proxy-generator-checker
```

3. Install the required dependencies:

```python
pip install -r requirements.txt
```

4. Run the `proxy_gui_new.py` script:

```python
python proxy_gui_new.py
```

5. Click "Browse Proxy File" to load a list of proxies from a local file, or enter a URL in the "URL" field and click "Load Proxies from URL" to load proxies from the specified URL.

6. Select the type of proxies you want to check (HTTP, HTTPS, SOCKS4, or SOCKS5) from the "Proxy Type" dropdown menu.

7. To automatically fetch and validate proxies, check the "Find Valid Proxies" checkbox.

8. Click "Check Proxies" to start the validation process. You can click "STOP" to halt the process at any time.

9. Valid proxies will be displayed in the "Valid Proxies" text box.

10. Click "Export as TXT" or "Export as CSV" to save the list of valid proxies to a file.

![Free Proxy Checker and Generator](https://i.ibb.co/f0XwmPW/proxy-free-checker.png)

## Contributing
We welcome contributions from the community! If you're interested in helping improve Proxy Checker, please follow these steps:

1. Fork the repository
2. Create a new branch with a descriptive name (e.g., git checkout -b feature/my-new-feature)
3. Make your changes and commit them with a clear and concise commit message
4. Push your changes to your fork
5. Create a pull request to merge your changes into the main repository


Before submitting a pull request, please ensure that your changes adhere to our coding standards and guidelines.

## License
This project is licensed under the GNU GENERAL PUBLIC LICENSE. See the LICENSE file for details.
