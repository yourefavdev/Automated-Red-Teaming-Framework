# web and ip exploit tool
This Python framework provides a suite of tools for offensive security operations, reconnaissance, intelligence gathering, and more, all within an interactive command-line interface.

✨ Features
Reconnaissance: Perform DNS lookups and fetch HTTP headers.
Intelligence Gathering:
URL Analysis: Conduct WHOIS lookups for domains and perform basic page source analysis (scripts, external links, iframes, comments).
IP Address Analysis: Perform IP WHOIS lookups, IP geolocation (requires IPinfo API key), port scanning (requires Nmap), and OS fingerprinting (requires Nmap and privileges).
Exploit Arsenal:
CVE Search: Search for CVEs using the NVD database (requires NVD API key for higher rate limits).
Payload Generators: Generate simple XSS, SQLi, and command injection payloads.
Reverse Shell Generator: Create common reverse shell payloads for various languages/tools.
Offensive Operations:
Phishing Page Generator: Launch a simple, customizable phishing web server to capture credentials.
DNS Spoofing (Conceptual): Provides conceptual Scapy code for DNS response spoofing, emphasizing the need for a separate MitM setup.
Denial of Service (DoS) Tools: Includes basic SYN Flood, UDP Flood, and HTTP GET Flood capabilities (use with extreme caution).
Directory Scanner: Scan target URLs for common backend paths and custom wordlists.
API Spammer: Send multiple GET or POST requests to an API endpoint with customizable headers and data.
POST Requester: Send a single POST request with detailed response output.
Custom Payload Executor (Placeholder): Module awaiting implementation.
C2 Communication (Placeholder): Module awaiting implementation.
Interactive Interface: A rich, colored, and interactive command-line interface powered by rich.

🛠️ Requirements & Installation
This project requires Python 3.x and several external libraries.
Clone the repository (or download main.py):
Bash
git clone https://github.com/your-username/your-repo-name.git
cd your-repo-name
Install Python Libraries:
Bash
pip install rich Faker requests ipwhois python-whois ipinfo beautifulsoup4 nvdlib scapy py

🚀 Usage
Run the script:
Bash
python main.py
Interact with the menu: Select the desired module by entering its corresponding number. Follow the prompts for each specific tool.

⚠️ Ethical Use & Disclaimer
This tool contains functionalities that can be used for offensive security purposes. It is designed for ethical hacking, penetration testing, and educational use ONLY.

ALWAYS obtain explicit, written permission from the owner of any system or network before performing any operations with this tool.
Misuse of these tools can lead to severe legal consequences.
The developers are not responsible for any misuse or damage caused by this software. Use it responsibly and ethically.
![2025-05-20 12_35_00-NVIDIA GeForce Overlay DT](https://github.com/user-attachments/assets/ed241fea-1b95-4ae2-ba27-f0236e62205e)
