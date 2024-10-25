Linux System Audit Tool
Overview

The Linux System Audit Tool is a Python-based web application that provides a comprehensive audit of a Linux system's security and configuration parameters. The tool aims to help users evaluate the security posture of their Linux systems, identify potential risks, and provide recommendations for system hardening.
Features

    OS and System Details: Gathers information about the operating system, host name, RAM, disk memory, and architecture.
    Firewall Assessment: Checks the status of firewalls (ufw, iptables, firewalld) to ensure security.
    Network Vulnerabilities: Audits network exposure and identifies unwanted network services.
    System Partition Audit: Verifies the creation of critical partitions like /var, /var/log, and /home.
    Security Hardening Recommendations: Provides feedback on firewall configurations, open ports, and other security parameters.
    Web Interface: User-friendly web interface developed using Python Flask for input and viewing audit results.

Technologies Used

    Python: Core programming language for the audit tool.
    Flask: Web framework for developing the user interface.
    HTML/CSS: For the web interface's front-end design.
    Shell Commands: Various Linux shell commands are used to gather system data.
    JavaScript (optional): Enhances UI interactivity.

Prerequisites

    Python 3.8+
    Linux Operating System (tested on Ubuntu 20.04+)
    pip package manager
    Flask Python package
    Admin privileges (sudo access) for running specific system commands

Installation

    Clone the Repository:

    bash

git clone https://github.com/yourusername/linux-system-audit-tool.git
cd linux-system-audit-tool

Install Required Python Packages: Use the provided requirements.txt file to install necessary dependencies:

bash

pip install -r requirements.txt

Run the Application: Start the Flask web server:

bash

python app.py

Access the Application: Open your web browser and navigate to:

arduino

    http://localhost:5000

Usage

    Input IP Address: On the home page, enter the IP address of the target system (local or within the same network) for auditing.
    Run Audit: Click the 'Go' button to initiate the audit process.
    View Results: The audit results are displayed on a new page, organized in a table format with columns for parameters, audit outcomes, and security recommendations.

Parameters Checked

The tool evaluates a variety of system parameters, including:

    BIOS Information: Retrieves BIOS details for hardware inspection.
    OS Details: Operating System version, architecture, and related info.
    Internet Exposure: Determines if the desktop is exposed to the internet.
    Firewall Status: Checks ufw, iptables, and firewalld for active/inactive status.
    Network Services: Lists unwanted network services and open ports.
    Partition Verification: Confirms that /var, /var/log, and /home partitions are created.
    Desktop Security Risk Assessment: Analyzes the overall system security based on audit results.

Directory Structure

bash

/linux-system-audit-tool
│
├── app.py                 # Main application file
├── requirements.txt       # Python dependencies
├── static/                # CSS, JavaScript files, and assets
│   └── style.css          # Custom styles for the web interface
├── templates/             # HTML templates for the web pages
│   ├── index.html         # Home page for IP input
│   └── result.html        # Page displaying the audit results
├── README.md              # Project documentation (this file)
└── utils/                 # Helper scripts and functions
    └── audit_functions.py # Python scripts to perform audits

Configuration

    Customization: You can modify the audit_functions.py file to adjust audit parameters or add new ones.
    Web Interface Styling: The style.css file in the static/ directory can be customized to change the appearance of the web interface.

Development

    Clone the repository and create a new branch for your feature:

    bash

git checkout -b feature-name

Commit your changes:

bash

git add .
git commit -m "Your detailed commit message"

Push your branch:

bash

    git push origin feature-name

    Create a Pull Request on GitHub for review.

Security

    Ensure proper permissions: Some audit commands require sudo privileges. Be careful when running commands with elevated permissions.
    Local Use Only: For now, the tool is designed for local network audits. For broader usage, additional security measures may be necessary.

Contributing

Contributions are welcome! Please open an issue or create a pull request for any changes, improvements, or suggestions.
License

This project is licensed under the MIT License - see the LICENSE file for details.
Contact

For any questions, issues, or suggestions, please reach out to:

    Email: adnaanafa@gmail.com
    GitHub: Adnaan5sal
