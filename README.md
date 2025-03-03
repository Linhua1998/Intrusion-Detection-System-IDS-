# Intrusion-Detection-System-IDS-

Project description for the portfolio
Intrusion Detection System (IDS)
This project is an Intrusion Detection System (IDS) designed to monitor network traffic and detect suspicious or malicious activity. IDS uses packet analysis to identify attacks and logs incidents into a database.

Functionality:

📡 Interception of traffic (TCP, UDP, ICMP)
🔎 Detection of attacks by preset signatures
, Logging events to the SQLite database
📊 Incident table output (IP addresses, type of attack, time)
🎨 Graphical representation of a 3D diagram for threat analysis

Technologies used:

Python (Scapy, Pandas, Matplotlib, SQLite)
Network analysis using Scapy
Data visualization with Matplotlib

How to use it?
Run IDS with the command: python Intrusion Detection System (IDS).py

The program analyzes the traffic for 10 seconds, after which:
Displays a table with recorded threats.
Generates a 3D diagram with the frequency of attacks
To stop, you can press Ctrl + C

Conclusion
This project demonstrates the basic principle of intrusion detection systems, combining traffic monitoring, threat analysis and data visualization. In the future, we may add support for real-world Snort rules, machine learning for behavioral attack analysis, or integration with SIEM systems.

🔥 This IDS is a great start in the field of cybersecurity! 🚀
