# Python C2 & Ransomware Simulation

![Purpose](https://img.shields.io/badge/Purpose-Educational%20Only-red.svg )

## ⚠️ Warning & Disclaimer

This project was created for **educational and research purposes only**. It aims to demonstrate the mechanics of ransomware and Command & Control (C2) systems to help understand how to protect against them.

**The use of this code for any illegal or malicious activities is strictly prohibited.** The author is not responsible for any misuse or damage caused by this project. You are using this code at your own risk.

---

## 📝 Overview

This project is a simple simulation of a ransomware attack using Python. It consists of two main components:

1.  **Attacker C2 (Command & Control):** A server with a Graphical User Interface (GUI) that allows the attacker (or security researcher) to send commands to the victim agent.
2.  **Victim Agent:** A script that runs on the target machine, connects back to the C2 server, and executes the received commands.

### Core Features

*   **Remote Connection:** Establishes a socket-based connection between the agent and the C2 server.
*   **File Browsing:** Remotely list files and directories on the victim's machine.
*   **File Encryption:** Encrypt specific files or entire directories using AES encryption (via the `cryptography` library).
*   **File Decryption:** Decrypt files with the correct password.
*   **Display Ransom Note:** Show a warning message (simulating a ransom note) on the victim's screen.

---

## 🛠️ Installation & Usage

### Prerequisites

*   Python 3.x
*   The libraries listed in the `requirements.txt` file.

### Installation Steps

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/mohammed-albareda/Python-C2-Ransomware-Sim.git
    cd Python-C2-Ransomware-Sim
    ```
    *(Replace `mohammed-albareda` with your actual GitHub username if different. )*

2.  **Install the required libraries:**
    ```bash
    pip install -r requirements.txt
    ```

### How to Run

1.  **Start the Attacker C2 Server:**
    *   On the attacker's machine, run the following command:
    ```bash
    python attacker_c2.py
    ```
    *   A GUI window will open, waiting for a connection from the victim.

2.  **Configure and Run the Victim Agent:**
    *   Open the `victim_agent.py` file in a text editor.
    *   Change the `ATTACKER_IP` variable to the IP address of the machine running the C2 server.
    ```python
    # !!! IMPORTANT: Change this to the attacker's IP address !!!
    ATTACKER_IP = "YOUR_ATTACKER_IP_ADDRESS"  # <--- Change this
    ```
    *   On the victim's machine (or another machine for testing), run the agent:
    ```bash
    python victim_agent.py
    ```

3.  **Take Control:**
    *   Once the agent connects, a status message will appear in the C2 control panel.
    *   You can now use the buttons to browse files, encrypt/decrypt data, and send a ransom note.

---

## 📜 License

This project is licensed under the MIT License. See the `LICENSE` file for more details.
