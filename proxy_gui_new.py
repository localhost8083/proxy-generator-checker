import tkinter as tk
from tkinter import ttk, filedialog, simpledialog
import requests
import socket as _socket
from urllib.request import urlopen
import csv
import threading
from concurrent.futures import ThreadPoolExecutor
import feedparser
import re
import socks
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from tkinter.ttk import Progressbar
from queue import Queue
from tkinter import StringVar
from tkinter import IntVar
import concurrent


class ProxyAdapter(HTTPAdapter):
    def __init__(self, proxy, *args, **kwargs):
        self.proxy = proxy
        super(ProxyAdapter, self).__init__(*args, **kwargs)

    def send(self, request, stream=False, timeout=None, verify=True, cert=None):
        request.proxies = {
            'http': self.proxy,
            'https': self.proxy
        }
        return super(ProxyAdapter, self).send(request, stream=stream, timeout=timeout, verify=verify, cert=cert)


class ProxyChecker:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("Proxy Checker")
        self.status_text = tk.StringVar()
        self.status_text.set("Ready")
        self.progress_queue = Queue()
        self.stop_check = threading.Event()
        self.proxies = []
        self.find_valid_proxies_var = IntVar()
        self.find_valid_proxies_var.trace(
            "w", self.update_check_proxies_button)
        self.create_widgets()

    def update_check_proxies_button(self, *args):
        if self.find_valid_proxies_var.get() or self.proxies:
            # Make button visible
            self.check_button.grid(
                row=4, column=2, columnspan=2, padx=10, pady=10)
            self.check_button.config(state='normal')
        else:
            self.check_button.grid(
                row=4, column=2, columnspan=2, padx=10, pady=10)
            self.check_button.config(state='disabled')

    def update_status_label(self, *args):
        self.status_label.config(text=self.status_text.get())

    def update_progress_bar(self, increment=1):
        self.progress_bar["value"] += increment
        self.progress_bar.update_idletasks()

    def create_widgets(self):
        style = ttk.Style()
        style.configure('TButton', font=('Helvetica', 10))
        style.configure('TLabel', font=('Helvetica', 10))
        style.configure('TEntry', font=('Helvetica', 10))

        # Load Proxies button

        self.load_button = ttk.Button(
            self.window, text="Browse Proxy File", command=self.load_proxies)
        self.load_button.grid(row=0, column=0, padx=10, pady=10, sticky='w')

        # URL label and entry
        self.url_label = ttk.Label(self.window, text="URL:")
        self.url_label.grid(row=1, column=0, padx=10, sticky='w')

        self.url_entry = ttk.Entry(self.window)
        self.url_entry.grid(row=1, column=1, padx=10, pady=10, sticky='w')

        # Load Proxies from URL button
        self.load_url_button = ttk.Button(
            self.window, text="Load Proxies from URL", command=self.start_load_proxies_from_url)
        self.load_url_button.grid(
            row=1, column=2, padx=10, pady=10, sticky='w')

        # Stop button
        self.stop_button = ttk.Button(
            self.window, text="STOP", command=self.stop_check_proxies, state='disabled')
        self.stop_button.grid(row=2, column=1, padx=10, pady=10, sticky='w')

        # Status label
        self.status_label = ttk.Label(
            self.window, textvariable=self.status_text)
        self.status_label.grid(row=7, column=0, padx=10, pady=10, sticky='w')

        # Proxy Type label and combobox
        self.proxy_type_label = ttk.Label(self.window, text="Proxy Type:")
        self.proxy_type_label.grid(
            row=3, column=1, padx=10, pady=10, sticky='w')

        self.proxy_type_var = StringVar()
        self.proxy_type_combobox = ttk.Combobox(
            self.window, textvariable=self.proxy_type_var, state='readonly')
        self.proxy_type_combobox['values'] = (
            'All', 'HTTP', 'HTTPS', 'SOCKS4', 'SOCKS5')
        self.proxy_type_combobox.current(0)
        self.proxy_type_combobox.grid(
            row=3, column=2, padx=10, pady=10, sticky='w')

        # Check Proxies button
        self.check_button = ttk.Button(
            self.window, text="Check Proxies", command=self.start_check_proxies, state='disabled')
        self.check_button.grid(row=4, column=2, padx=10, pady=10, sticky='w')

        # Find Valid Proxies checkbox
        self.find_valid_proxies_checkbox = ttk.Checkbutton(
            self.window, text="Find Valid Proxies", variable=self.find_valid_proxies_var)
        self.find_valid_proxies_checkbox.grid(
            row=4, column=1, padx=10, pady=10, sticky='w')

        # Valid Proxies label and text box
        self.output_label = ttk.Label(self.window, text="Valid Proxies:")
        self.output_label.grid(row=4, column=0, padx=10, pady=10, sticky='w')

        self.output_text = tk.Text(
            self.window, wrap=tk.WORD, width=60, height=10)
        self.output_text.grid(row=5, column=0, padx=10,
                              pady=10, columnspan=3, sticky='w')

        # Export buttons
        self.export_txt_button = ttk.Button(
            self.window, text="Export as TXT", command=self.export_txt, state='disabled')
        self.export_txt_button.grid(
            row=6, column=0, padx=10, pady=10, sticky='w')
        self.export_csv_button = ttk.Button(
            self.window, text="Export as CSV", command=self.export_csv, state='disabled')
        self.export_csv_button.grid(
            row=6, column=1, padx=10, pady=10, sticky='w')

        # Progress bar
        self.progress_bar = ttk.Progressbar(self.window, mode="determinate")
        self.progress_bar.grid(row=3, column=0, padx=10,
                               pady=10, sticky='w', columnspan=3)

    def load_proxies_from_url(self):
        url = self.url_entry.get()
        self.check_button.config(state='disabled')
        if not url:
            self.status_text.set("URL is empty.")
            self.load_url_button.config(state='normal')
            return

        try:
            if url.endswith('.txt'):
                response = requests.get(url)
                response.raise_for_status()
                content = response.text
            else:
                feed = feedparser.parse(url)
                if all('content' in entry for entry in feed.entries):
                    content = '\n'.join(
                        entry.content[0].value for entry in feed.entries)
                else:
                    content = '\n'.join(
                        entry.summary for entry in feed.entries if 'summary' in entry)

            proxies = self.extract_proxies_from_text(content)

            if self.proxies:
                self.check_button.config(state='normal')
                self.status_text.set(f"Loaded {len(self.proxies)} proxies")
            else:
                self.status_text.set("No proxies found.")
        except Exception as e:
            self.status_text.set(f"Error: {str(e)}")

        finally:
            self.load_url_button.config(state='normal')

    def extract_proxies_from_text(self, text):
        proxies = []
        lines = text.splitlines()
        for line in lines:
            matches = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\:\d{1,5}\b', line)
            proxies.extend(matches)
        return proxies

    def load_proxies(self):
        choice = filedialog.askopenfilename(
            title="Select a file or cancel to enter proxies manually", filetypes=[("Text files", "*.txt")])

        self.check_button.config(state='disabled')
        if choice:
            with open(choice, "r") as file:
                self.proxies = file.read().splitlines()
        else:
            self.proxies = self.window.tk.splitlist(tk.simpledialog.askstring(
                "Enter proxies", "Enter proxies separated by commas:\nExample: 127.0.0.1:8080,127.0.0.1:8081"))

        if self.proxies:
            self.check_button.config(state='normal')
            self.status_text.set(f"Loaded {len(self.proxies)} proxies")

    def check_proxies(self):
        self.window.after_idle(self.status_text.set, "Checking proxies...")

        self.valid_proxies = self.test_proxies(self.proxies)

        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, "\n".join(self.valid_proxies))

        if self.valid_proxies:
            self.export_txt_button.config(state='normal')
            self.export_csv_button.config(state='normal')
        else:
            self.export_txt_button.config(state='disabled')
            self.export_csv_button.config(state='disabled')

        self.window.after_idle(self.check_button.config, state='normal')
        self.window.after_idle(self.load_button.config, state='normal')
        self.window.after_idle(self.stop_button.config, state='disabled')
        self.status_text.set(
            f"Checked proxies. {len(self.valid_proxies)} valid proxies found.")
        self.update_status_label()

    def toggle_check_proxies_button(self):
        if self.find_valid_proxies_var.get():
            self.check_button.config(state='disabled')
        else:
            if self.proxies:
                self.check_button.config(state='normal')
            else:
                self.check_button.config(state='disabled')

    def fetch_and_validate_proxies(self):
        self.window.after_idle(self.status_text.set,
                               "Fetching proxies from the internet...")
        proxy_type = self.proxy_type_var.get()
        proxy_type = proxy_type.lower() if proxy_type != 'All' else 'http'

        try:
            url = f'https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all'
            response = requests.get(url)
            response.raise_for_status()
            proxies = response.text.splitlines()
            self.proxies = proxies
            self.status_text.set(
                f"Found {len(proxies)} proxies from the internet. Checking...")
            self.check_proxies()
        except Exception as e:
            # self.status_text.set(f"Error fetching proxies: {str(e)}")
            self.check_button.config(state='normal')
            self.load_button.config(state='normal')
            self.stop_button.config(state='disabled')

    def start_check_proxies(self):
        self.stop_check.clear()
        self.check_button.config(state='disabled')
        self.load_button.config(state='disabled')
        self.stop_button.config(state='normal')
        self.stop_check.clear()

        if self.find_valid_proxies_var.get():
            check_thread = threading.Thread(
                target=self.fetch_and_validate_proxies)
        else:
            check_thread = threading.Thread(target=self.check_proxies)

        check_thread.start()

    def stop_check_proxies(self):
        self.stop_check.set()

    def is_proxy_valid(self, proxy):
        if self.stop_check.is_set():
            return False

        proxy_url = f"http://{proxy}"
        proxy_type = self.proxy_type_var.get()

        if proxy_type in ('All', 'HTTP', 'HTTPS'):
            session = requests.Session()
            session.mount('http://', ProxyAdapter(proxy_url))
            session.mount('https://', ProxyAdapter(proxy_url))
            retry_strategy = Retry(
                total=3,
                backoff_factor=1,
                status_forcelist=[429, 500, 502, 503, 504],
                allowed_methods=["HEAD", "GET", "OPTIONS"]
            )
            session.mount("https://", HTTPAdapter(max_retries=retry_strategy))

            try:
                response = session.get("https://httpbin.org/ip", timeout=5)
                if response.status_code == 200:
                    # self.status_text.set(
                    #     f"Testing: {proxy} - Valid (HTTP/HTTPS)")
                    return True
            except Exception:
                pass

        if proxy_type in ('All', 'SOCKS4', 'SOCKS5'):
            proxy_ip, proxy_port = proxy.split(":")
            socks_types = [socks.SOCKS4, socks.SOCKS5] if proxy_type == 'All' else [
                getattr(socks, proxy_type)]

            for socks_type in socks_types:
                original_socket = _socket.socket
                socks.set_default_proxy(socks_type, proxy_ip, int(proxy_port))
                _socket.socket = socks.socksocket
                try:
                    response = urlopen("https://httpbin.org/ip", timeout=5)
                    if response.status == 200:
                        # self.status_text.set(
                        #     f"Testing: {proxy} - Valid (SOCKS{socks_type - socks.SOCKS4 + 4})")
                        return True
                except Exception:
                    pass
                finally:
                    _socket.socket = original_socket

        self.progress_queue.put(1)
        # self.status_text.set(f"Testing: {proxy} - Invalid")
        return False

    def start_load_proxies_from_url(self):
        self.load_url_button.config(state='disabled')
        self.status_text.set("Loading proxies from URL...")
        load_thread = threading.Thread(target=self.load_proxies_from_url)
        load_thread.start()

    def export_txt(self):
        file = filedialog.asksaveasfile(defaultextension=".txt", filetypes=[
            ("Text files", "*.txt")])
        if file:
            file.write('\n'.join(self.valid_proxies))
            file.close()

    def export_csv(self):
        file = filedialog.asksaveasfile(
            defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if file:
            writer = csv.writer(file)
            for proxy in self.valid_proxies:
                writer.writerow([proxy])
            file.close()

    def get_anonymity_level(self, proxy):
        try:
            with requests.get(self.test_url, proxies={"http": proxy, "https": proxy}, timeout=self.timeout) as response:
                headers = response.headers
                via_header = headers.get("Via")
                x_forwarded_for_header = headers.get("X-Forwarded-For")

                if not via_header and not x_forwarded_for_header:
                    return "elite"
                elif via_header and x_forwarded_for_header:
                    return "anonymous"
                else:
                    return "transparent"
        except Exception as e:
            return None

    def test_proxies(self, proxies):
        self.progress_bar["maximum"] = len(proxies)
        self.progress_bar["value"] = 0
        valid_proxies = []
        with ThreadPoolExecutor() as executor:
            for proxy, valid in zip(proxies, executor.map(self.is_proxy_valid, proxies)):
                if valid:
                    valid_proxies.append(proxy)
                    self.output_text.insert(tk.END, proxy + "\n")
                    # Add this line to auto-scroll
                    self.output_text.see(tk.END)
                self.update_progress_bar(1)
        self.progress_bar["value"] = len(valid_proxies)
        return valid_proxies

    def run(self):
        self.window.mainloop()


if __name__ == "__main__":
    app = ProxyChecker()
    app.run()
