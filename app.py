from flask import Flask, render_template, request, redirect, url_for # type: ignore
import subprocess
import socket
import netifaces

app = Flask(__name__)

def run_command(command):
    """Run a shell command and return its output as a list of lines."""
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True, shell=True)
        return result.stdout.splitlines()
    except subprocess.CalledProcessError as e:
        return [f"Error running command '{command}': {e.stderr.strip()}"]
    except FileNotFoundError:
        return [f"Command not found: {command}"]  # Handle command not found error

def get_local_ips():
    """Retrieve the local IP addresses of the current system, including loopback."""
    local_ips = set()
    
    # Get IP addresses from all network interfaces
    for interface in netifaces.interfaces():
        addresses = netifaces.ifaddresses(interface)
        if netifaces.AF_INET in addresses:
            for link in addresses[netifaces.AF_INET]:
                local_ips.add(link['addr'])
    
    # Add common loopback addresses
    local_ips.add("localhost")
    local_ips.add("127.0.0.1")
    
    return list(local_ips)

def format_multiline_output(output_lines, items_per_line=1):
    """Format multiline output by inserting <br> every 'items_per_line' items."""
    formatted_output = []
    for i in range(0, len(output_lines), items_per_line):
        formatted_output.append("<br>".join(output_lines[i:i + items_per_line]))
    return "<br>".join(formatted_output)

# Route for the Home Page
@app.route('/')
def home():
    return render_template('home.html')  # Render the Home Page for IP input

# Route to display audit results based on the provided IP address
@app.route('/audit', methods=['POST'])
def audit():
    ip_address = request.form.get('ip_address')  # Get IP address from the form
    local_ips = get_local_ips()  # Get the local IP addresses of the current system

    # Debugging: Print the local IPs
    print(f"Local IPs: {local_ips}")
    print(f"Entered IP Address: {ip_address}")

    # Check if the entered IP is a local IP
    if ip_address not in local_ips:
        return render_template('error.html', message="No device with such IP address. Please enter correct IP address.")

    # Audit logic starts here (same as before)
    output = []
    output.append(f"Audit Results for IP: {ip_address}")

    # 1. OS Details (Multiple lines in one cell, separated by <br>)
    os_details = run_command("cat /etc/os-release")
    os_details_text = format_multiline_output(os_details, 1)  # Break after each detail
    output.append(f"1. OS Details:<br>{os_details_text}")


    # 2. No Desktop Exposed to Internet
    external_ips = run_command("curl -s ifconfig.me")  # Fetch external IP
    internal_ips = run_command("hostname -I")  # Get internal IPs

    # Get the first external IP as a string
    external_ip = external_ips[0] if external_ips and 'Error' not in external_ips[0] else None

    # Debugging output
    print(f"External IP: {external_ip}")
    print(f"Internal IPs: {internal_ips}")

    if external_ip:
    # Check if the external IP is equal to any of the internal IPs
     if any(external_ip.strip() == ip.strip() for ip in internal_ips):
        output.append("2. Desktop Exposed to Internet: No, the system is not exposed to the internet")
     else:
        output.append("2. Desktop Exposed to Internet: Yes, the system is exposed to the internet")
    else:
      output.append("2. Desktop Exposed to Internet: No the system is not exposed to the internet")


    # 3. Stop Unwanted Network Services and Ports
    services = ["cups", "telnet , nfs , http , ftp , rlogin , tftp , rcpbind "]
    for service in services:
      service_status = run_command(f"systemctl is-active {service}")
    
      # Check if "active" is in the output (service_status will be a list, so we check the first item)
      if service_status and service_status[0] == "active":
        output.append(f"3. The - {service}  - Services Running: Yes, Service is running")
      else:
        output.append(f"3. The - {service} - Services Running: No, Service is not running")


    # 4. Desktop Security Risk Assessment (Firewall via ufw)
    firewall_status = run_command("sudo ufw status")

    # Print the firewall status for debugging
    print(f"Firewall Status: {firewall_status}")

    # Check if we received output from the command
    if firewall_status:
    # Check for the presence of 'inactive' or 'active'
     if any("inactive" in line.lower() for line in firewall_status):
        output.append("4. Desktop Security Risk Assessment (Firewall): No, the firewall UFW is inactive")
     elif any("active" in line.lower() for line in firewall_status):
          output.append("4. Desktop Security Risk Assessment (Firewall): Yes, the firewall UFW is active")
     else:
          output.append("4. Desktop Security Risk Assessment (Firewall): Unable to determine firewall status (unexpected output)")
    else:
      output.append("4. Desktop Security Risk Assessment (Firewall): Unable to determine firewall status (command failed)")



    # 5. Disable USB Media
    usb_access_status = run_command("lsmod | grep usb_storage")
    if usb_access_status:
        output.append("5. USB Access Disabled: No, it is not disabled")
    else:
        output.append("5. USB Access Disabled: Yes, it is disabled")


    # 6. Check guest account
    guest_account_status = run_command("id guest")

    # Print output for debugging
    print(f"Guest Account Status: {guest_account_status}")

    if guest_account_status and "no such user" in guest_account_status[0].lower():
       output.append("6. Guest Account Disabled: Guest account not found")
    elif guest_account_status:
      output.append("6. Guest Account Disabled: No, it is not disabled")
    else:
      output.append("6. Guest Account Disabled: Yes, it is disabled")

    # 7. Create Separate Partitions for /var, /var/log, and /home
    partitions = ["/var", "/var/log", "/home"]
    missing_partitions = []
    created_partitions = []

# Check each partition and categorize it as created or missing
    for partition in partitions:
    # Use lsblk to check if the partition is mounted
      command = f'lsblk -o MOUNTPOINT | grep "^{partition}$"'
      mount_status = run_command(command)

    # Check if mount_status is not None and is a valid output
      if mount_status and isinstance(mount_status, list) and len(mount_status) > 0:
        created_partitions.append(partition)
      else:
        missing_partitions.append(partition)

# Construct the output message based on the results
    if not missing_partitions:
      missing_list = "/var", "/var/log", "/home" 
      output.append(f"7. Are the  Partitions: No, the following partitions are not created: {missing_list}.")
    else:
      output.append("7. Are the Partitions: Yes, all partitions are created.")



    # # 8. Monitor Sudoers Changes
    # sudoers_monitor_status = run_command("sudo auditctl -l | grep /etc/sudoers")

    # # Print the status for debugging
    # print(f"Sudoers Monitor Status: {sudoers_monitor_status}")

    # if sudoers_monitor_status:
    #    output.append("8. Monitor Sudoers File: Yes, sudoers files are being monitored")
    # else:
    #    output.append("8. Monitor Sudoers File: No, sudoers files are not being monitored. Consider adding an audit rule.")


    # 8. Sticky Bit on World-Writable Directories
    sticky_bit_status = run_command("ls -ld /tmp")

    # Check if the sticky bit is set
    if sticky_bit_status and 't' in sticky_bit_status[0]:
      output.append("8. Sticky Bit on /tmp: Yes, the sticky bit is set")
    else:
      output.append("8. Sticky Bit on /tmp: No, the sticky bit is not set")


    # 10. Remove Legacy Services
    #legacy_services = ["telnet", "rlogin", "tftp"]
    #for service in legacy_services:
        #service_status = run_command(f"systemctl is-active --quiet {service}")
        #if service_status == []:
            #output.append(f"10. The {service} Disabled: No, needs to be disabled")
        #else:
          #  output.append(f"10. The {service} Disabled: Yes, outdated services are disabled")

    # 11. Disable IP Forwarding
    ip_forward_status = run_command("cat /proc/sys/net/ipv4/ip_forward")    
    if ip_forward_status:
        ip_forward_value = ip_forward_status[0].strip()
        if ip_forward_value == "0":
            output.append("9. IP Forwarding Disabled: Yes, it is disabled")
        elif ip_forward_value == "1":
            output.append("9. IP Forwarding Disabled: No, it needs to be disabled")
        else:
            output.append("9. IP Forwarding Status: Unknown")
    else:
         output.append("9. Error reading IP forwarding status.")


    # 12. SSH Protocol 2 or Higher
    ssh_protocol_status = run_command("ssh -o StrictHostKeyChecking=no -o BatchMode=yes -v localhost 2>&1 | grep 'Remote protocol version' | awk '{print $5}' | tr -d ','")
    if "2.0" in ssh_protocol_status:
        output.append("10. SSH Using Protocol 2: Yes,SSH is using protocol2")
    else:
        output.append("10. SSH Using Protocol 2: No, upadte SSH protocols to protocol2")

    # 13. Limit Unsuccessful Login Attempts
    pam_tally_status = run_command("grep 'LOGIN_RETRIES' /etc/login.defs")
    if pam_tally_status:
        output.append("11. Unsuccessful Login Attempts Limited: Yes, Limiting unsuccessful login attempts are enabled ")
    else:
        output.append("11. Unsuccessful Login Attempts Limited: No, Limiting unsuccessful login attempts are not limited")

    # 14. System Password Policy
    password_policy_status = run_command("grep '^PASS_MAX_DAYS' /etc/login.defs")

    if password_policy_status:
    # Ensure that the first element of the list is used and split accordingly
      pass_max_days_line = password_policy_status[0] if isinstance(password_policy_status, list) else password_policy_status
      pass_max_days = int(pass_max_days_line.split()[1])  # Extracting the value of PASS_MAX_DAYS

    # Check if PASS_MAX_DAYS is set to 90
      if pass_max_days <= 90:
        output.append("12. System Password Policy: Yes, PASS_MAX_DAYS is set to 90 ")
      else:
        # If PASS_MAX_DAYS is not 90, display its current value
        output.append(f"12. System Password Policy: Yes, PASS_MAX_DAYS is set to {pass_max_days}")
    else:
      output.append("12. System Password Policy: No, not set needs be set")





    # # 15. Password Expiration Period
    # #expiration_period_status = run_command("grep '^PASS_MAX_DAYS' /etc/login.defs")
    # if expiration_period_status:
    #     output.append("15. Password Expiration Policy Set: Yes, it is set")
    # else:
    #     output.append("15. Password Expiration Policy Set: No, needs to set")

    # 16. System and Software Updates
    updates_status = run_command("sudo apt-get update && sudo apt-get upgrade -s")

    # Check if the output contains '0 upgraded'
    if updates_status and any("0 upgraded" in line for line in updates_status):
       output.append("13. System and Software Up-to-date: Yes, system is up-to-date")
    else:
       output.append("13. System and Software Up-to-date: No, system needs an update")

    # 17. Warning Banner at Login
    warning_banner_status = run_command("test -s /etc/motd && echo 'Yes' || echo 'No'")
    if "Yes" in warning_banner_status:
        output.append("14. Pre-login Warning Banner: Yes, it displays a warning banner")
    else:
        output.append("14. Pre-login Warning Banner: No, does not show warning banner")

    # 18. Post-login Warning Banner (SSH)
    post_warning_banner_status = run_command("grep 'Banner' /etc/ssh/sshd_config")

    # Check if there is any valid (non-commented) Banner line in the output
    if post_warning_banner_status:
    # Filter out commented lines (those starting with '#')
      valid_banner_lines = [line for line in post_warning_banner_status if not line.strip().startswith('#')]
    
      if valid_banner_lines:
         output.append("15. Post-login SSH Banner: Yes, it displays warning")
      else:
        output.append("15. Post-login SSH Banner: No, it does not display warning (commented)")
    else:
        output.append("15. Post-login SSH Banner: No, it does not display warning")

    # 19. Logging Configuration (syslogd check)
    syslog_status = run_command("dpkg -l | grep syslog")

    # Check if the command executed successfully
    if syslog_status:
     # If there is valid output, check if it contains any installed syslog packages
      if isinstance(syslog_status, list) and any('syslog' in line for line in syslog_status):
        output.append("16. Logging Configuration (syslog): Yes, logging configurations are properly configured")
      else:
        output.append("16. Logging Configuration (syslog): No, logging configuration needs to be configured")
    else:
      output.append("16. Logging Configuration (syslog): No, logging configuration needs to be configured")


    # 20. Disable SSH Root Login
    ssh_root_login_status = run_command("grep '^PermitRootLogin no' /etc/ssh/sshd_config")
    if ssh_root_login_status:
        output.append("17. SSH Root Login Disabled: Yes, it is disabled")
    else:
        output.append("17. SSH Root Login Disabled: No, it is not disabled")

   
    # 21. Inactive Terminal Timeout
    inactive_timeout_status = run_command("grep 'ClientAliveInterval' /etc/ssh/sshd_config")
    if inactive_timeout_status:
        output.append("18. Inactive Terminal Timeout Set: Yes, auto logs the user after a period of inactivity")
    else:
        output.append("18. Inactive Terminal Timeout Set: No, inactive terminal needs to be set")

    # 22. OSSEC HIDS Installed
    ossec_status = run_command("command -v ossec-control")

    # Check if ossec_status is a string and not empty
    if isinstance(ossec_status, str) and ossec_status.strip():  # Ensure it's a string and not empty
      output.append("19. OSSEC HIDS Installed: Yes, it is installed")
    else:
      output.append("19. OSSEC HIDS Installed: No, needs to be installed")



   # 23. Restrict SSH Access to Selected Users
    ssh_access_status = run_command("grep '^AllowUsers' /etc/ssh/sshd_config")

    # If the command found no output (i.e., the list is empty or contains no valid 'AllowUsers' lines)
    if ssh_access_status and len(ssh_access_status) > 0:
      output.append("20. SSH Access Restricted to Selected Users: No, SSH is not restricted to selected users")
    else:
      output.append("20. SSH Access Restricted to Selected Users: Yes, it is restricted to selected users")

    # 24. Network Time Protocol (NTP) Configured
    # Capture the full output from timedatectl
    ntp_status = run_command("timedatectl | grep 'NTP service: active'")

    
    if ntp_status :
      output.append("21. NTP Configured: Yes, system is synchronized using NTP")
    else:
      output.append("21. NTP Configured: No, system is not synchronized using NTP")


    # 25. rsyslog and Centralized Logging Configured
    rsyslog_status = run_command("systemctl is-active --quiet rsyslog")
    if rsyslog_status == []:
        output.append("22. rsyslog Installed and Active: Yes, it is installed and active")
    else:
        output.append("22. rsyslog Installed and Active: No, it is not active")

    # 26. IPv6 Disabled
    ipv6_status = run_command("sysctl net.ipv6.conf.all.disable_ipv6")

    # Since 'run_command' returns a list of lines, we need to check the first line for "1"
    if ipv6_status and "1" in ipv6_status[0]:
      output.append("23. IPv6 Disabled: Yes, IPv6 is disabled")
    else:
      output.append("23. IPv6 Disabled: No, IPv6 is not disabled")

    # 27. Password Hashing Algorithm (SHA-512)
    password_hashing_status = run_command("grep 'ENCRYPT_METHOD SHA512' /etc/login.defs")

    if password_hashing_status:
      output.append("24. Password Hashing Algorithm SHA-512: Yes, password hashing algorithm SHA-512 is set")
    else:
      output.append("24. Password Hashing Algorithm SHA-512: No, password hashing algorithm SHA-512 is not set")


    # 28. Disable USB Access
    usb_access_status = run_command("lsmod | grep usb_storage")
    if usb_access_status:
        output.append("25. USB Access Disabled: No, it is not disabled")
    else:
        output.append("25. USB Access Disabled: Yes, it is disabled")

   # 29. Single-User Mode Requires Authentication
    single_user_auth_status = run_command("sudo grep -r 'sulogin' /usr/share/initramfs-tools/scripts/")

   # Check if any valid output is found (i.e., 'sulogin' found in the files)
    if single_user_auth_status and len(single_user_auth_status) > 0:
      output.append("26. Single-User Mode Requires Authentication: No, it is not set")
    else:
      output.append("26. Single-User Mode Requires Authentication: Yes, it is set")

    # 30. SSH X11 Forwarding Disabled
    ssh_x11_forwarding_status = run_command("grep '^X11Forwarding no' /etc/ssh/sshd_config")
    if ssh_x11_forwarding_status:
        output.append("27. SSH X11 Forwarding Disabled: Yes, it is diabled")
    else:
        output.append("27. SSH X11 Forwarding Disabled: No, it is enabled")

    return render_template('index.html', output="\n".join(output))



if __name__ == '__main__':
    app.run(debug=True)
