 Hussain-s-IDS_INTRUDEX
A professional desktop IDS built with Python, CustomTkinter, and Scapy for real-time packet monitoring and alerting.
 HUSSAIN IDS - Intrudex 🔐

A professional Python-based Intrusion Detection System (IDS) with a modern GUI, real-time packet monitoring, interface selection, and log export support.

Overview 📌

**Intrudex** is a desktop network monitoring tool built with Python, CustomTkinter, and Scapy. It captures live TCP traffic, detects basic suspicious patterns, and displays alerts in a clean dashboard-style interface.

This project was developed as a final project for information security coursework.

 Features ✨

- Modern dark-themed GUI 🌙
- Real-time packet sniffing using Scapy 📡
- Friendly interface selection for Windows adapters 🖧
- Automatic mapping of Windows NPF devices to readable names 🪟
- Live alert dashboard 📊
- Uptime counter ⏱️
- Save logs to JSON 💾
- Custom app icon support 🖼️

 Tech Stack 🛠️

- Python 3.14+
- CustomTkinter
- Scapy
- Tkinter
- PyInstaller for packaging

 How It Works ⚙️

Intrudex monitors selected network traffic and applies simple detection rules:

- SYN packets are flagged as potential scan activity ⚠️
- SSH traffic is highlighted 🔒
- HTTP/HTTPS traffic is tracked 🌐
- All captured alerts are shown in real time and can be saved to a JSON file 📝

Installation 📦

1. Clone the repository
```bash
git clone https://github.com/your-username/your-repo-name.git
cd your-repo-name
```

2. Install dependencies
```bash
pip install customtkinter scapy pyinstaller
```

3. Install Npcap
Scapy on Windows requires Npcap for packet capture.

Download and install Npcap, then restart your system.

 Running the Project 🚀

 Run from Python
```bash
python ids.py
```

 Build EXE with PyInstaller
```bash
pyinstaller --onefile --noconsole --name Intrudex --icon=intrudex.ico --add-data "intrudex.ico;." ids.py
```

The final executable will be created inside the `dist` folder.

Usage 🧭

1. Open the application.
2. Select the correct network interface from the dropdown.
3. Click **Start Monitoring**.
4. Generate traffic on your network.
5. View live alerts in the log panel.
6. Click **Stop Monitoring** when finished.
7. Save logs using the save button or `Ctrl+S`.

Project Structure 🗂️

```bash
.
├── ids.py
├── intrudex.ico
├── README.md
└── security_logs.json
```

 Notes 📝

- Run the application as Administrator for proper packet capture on Windows.
- If no packets appear, try another interface from the dropdown.
- The interface names are mapped automatically from Windows NPF adapters.

 Screenshots 🖼️

Add screenshots here if available.
<img width="1362" height="724" alt="image" src="https://github.com/user-attachments/assets/880dd63b-6aeb-49eb-a4b5-96fb1bb2500c" />
<img width="1366" height="725" alt="image" src="https://github.com/user-attachments/assets/d3115176-8cdf-418c-b45a-3ebd9d220246" />
<img width="1366" height="719" alt="image" src="https://github.com/user-attachments/assets/9c21babd-2348-470c-98a3-21735e336551" />
<img width="1366" height="725" alt="image" src="https://github.com/user-attachments/assets/d2535956-1c0f-4a3a-a763-ef242ad9a676" />


Future Improvements 🔮

- Advanced anomaly detection.
- IP blocking support.
- Live statistics charts.
- Export to CSV and PDF.
- Better rule engine.

License 📄

This project is for educational purposes.

## Author 👨‍💻

Developed by Hafeez.
