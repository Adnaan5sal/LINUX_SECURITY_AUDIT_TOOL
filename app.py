from flask import Flask, render_template, request
import subprocess
import paramiko
import netifaces

app = Flask(__name__)

# Run command locally
def run_command_local(command):
    print("Running command locally")
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout.strip(), result.stderr.strip()

# Run command remotely via SSH
def run_command_remote(command, ip_address, username, password):
    print(f"Running command on remote system: {ip_address}")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(ip_address, username=username, password=password)
        stdin, stdout, stderr = client.exec_command(command)
        output = stdout.read().decode().strip()
        error = stderr.read().decode().strip()
        client.close()
        return output, error
    except paramiko.AuthenticationException:
        return None, "Authentication failed: Incorrect username or password."
    except paramiko.SSHException as e:
        return None, f"SSH connection failed: {str(e)}"
    except Exception as e:
        return None, f"Unexpected error: {str(e)}"

# Get local IP addresses for validation
def get_local_ips():
    local_ips = set()
    for interface in netifaces.interfaces():
        addresses = netifaces.ifaddresses(interface)
        if netifaces.AF_INET in addresses:
            for link in addresses[netifaces.AF_INET]:
                local_ips.add(link['addr'])
    local_ips.update(["localhost", "127.0.0.1"])
    return list(local_ips)

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/audit', methods=['POST'])
def audit():
    ip_address = request.form.get('ip_address')
    username = request.form.get('username')
    password = request.form.get('password')

    # Determine if we should run remotely based on IP and credentials
    is_remote = ip_address not in get_local_ips() and username and password

    output = [f"Audit Results for IP: {ip_address}"]
    print(f"Performing audit on {'remote' if is_remote else 'local'} system: {ip_address}")

    # Use appropriate function for each command based on is_remote
    if is_remote:
        run_command = lambda cmd: run_command_remote(cmd, ip_address, username, password)
    else:
        run_command = run_command_local

    # 1. OS Details
    os_details, error = run_command("cat /etc/os-release")
    if error:
        return render_template('error.html', message=error)
    output.append(f"1. OS Details: {os_details.replace('\n', '<br>')}")

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
        output.append("2. Desktop connected to Internet: No, the system is not connected to internet")
     else:
        output.append("2. Desktop connected to Internet: Yes, the system is connected to the internet")
    else:
      output.append("2. Desktop connected to Internet: No the system is not connected to the internet")


    # 3. Stop Unwanted Network Services and Ports
    services = ["cups", "telnet , nfs , http , ftp , rlogin , tftp , rcpbind "]
    for service in services:
      service_status = run_command(f"systemctl is-active {service}")
    
      # Check if "active" is in the output (service_status will be a list, so we check the first item)
      if service_status and service_status[0] == "active":
        output.append(f"3. Unwanted network services  disabled: No, Service is not disabled")
      else:
        output.append(f"3. Unwanted network services disabled: Yes, Service is disabled")


    # # 4. Desktop Security Risk Assessment (Firewall via ufw)
    # firewall_status = run_command("sudo ufw status")

    # # Print the firewall status for debugging
    # #print(f"Firewall Status: {firewall_status}")

    # # Check if we received output from the command
    # if firewall_status:
    # # Check for the presence of 'inactive' or 'active'
    #  if any("inactive" in line.lower() for line in firewall_status):
    #     output.append("4. UFW is active: No, the firewall UFW is inactive")
    #  elif any("active" in line.lower() for line in firewall_status):
    #       output.append("4. UFW is: Yes, the firewall UFW is active")
    #  else:
    #       output.append("4. Desktop Security Risk Assessment (Firewall): Unable to determine firewall status (unexpected output)")
    # else:
    #   output.append("4. Desktop Security Risk Assessment (Firewall): Unable to determine firewall status (command failed)")

 # Example: Firewall Status
    firewall_status, error = run_command("systemctl is-active ufw")
    if firewall_status:
        if "inactive" in firewall_status.lower():
            output.append("4. UFW Status: No, the firewall UFW is inactive")
        elif "active" in firewall_status.lower():
            output.append("4. UFW Status: Yes, the firewall UFW is active")
        else:
            output.append("4. Firewall Status: Unable to determine status (unexpected output)")
    else:
        output.append("4. Firewall Status: Unable to determine status (command failed)")

    # 5. Disable USB Media
    usb_access_status = run_command("lsmod | grep usb_storage")
    if usb_access_status:
        output.append("5. USB Access Disabled: No, it is not disabled")
    else:
        output.append("5. USB Access Disabled: Yes, it is disabled")


    # 6. Check guest account
    guest_account_status = run_command("id guest")

    # Print output for debugging
    #print(f"Guest Account Status: {guest_account_status}")

    if guest_account_status and "no such user" in guest_account_status[0].lower():
       output.append("6. Guest Account Disabled: Guest account not found")
    elif guest_account_status:
      output.append("6. Guest Account Disabled: Guest account not found")
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
      output.append(f"7. Partitions (/var,/var/log,/home) created: Yes, the partiotions are created.")
    else:
      output.append("7. Partitions (/var, /var/log,/home) created: No, the  partitions are not created.")



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


    # . Remove Legacy Services
    #legacy_services = ["telnet", "rlogin", "tftp"]
    #for service in legacy_services:
        #service_status = run_command(f"systemctl is-active --quiet {service}")
        #if service_status == []:
            #output.append(f"10. The {service} Disabled: No, needs to be disabled")
        #else:
          #  output.append(f"10. The {service} Disabled: Yes, outdated services are disabled")

    # 9. Disable IP Forwarding
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


    # 10. SSH Protocol 2 or Higher
    ssh_protocol_status = run_command("ssh -o StrictHostKeyChecking=no -o BatchMode=yes -v localhost 2>&1 | grep 'Remote protocol version' | awk '{print $5}' | tr -d ','")
    if "2.0" in ssh_protocol_status:
        output.append("10. SSH Using Protocol 2: Yes,SSH is using protocol2")
    else:
        output.append("10. SSH Using Protocol 2: No, upadte SSH protocols to protocol2")

    # 11. Limit Unsuccessful Login Attempts
    pam_tally_status = run_command("grep -E '^[^#]*LOGIN_RETRIES' /etc/login.defs")
    if pam_tally_status:
        output.append("11. Unsuccessful Login Attempts Limited: Yes, Limiting unsuccessful login attempts are enabled ")
    else:
        output.append("11. Unsuccessful Login Attempts Limited: No, Limiting unsuccessful login attempts are not limited")

    # 12. System Password Policy
    password_policy_status = run_command("grep '^PASS_MAX_DAYS' /etc/login.defs")

    if password_policy_status:
    # Ensure that the first element of the list or tuple is used and split accordingly
      pass_max_days_line = password_policy_status[0] if isinstance(password_policy_status, (list, tuple)) else password_policy_status

    # Check if the retrieved line is a string that can be split
      if isinstance(pass_max_days_line, str):
        try:
            pass_max_days = int(pass_max_days_line.split()[1])  # Extracting the value of PASS_MAX_DAYS

            # Check if PASS_MAX_DAYS is set to 90
            if pass_max_days <= 90:
                output.append("12. System Password Policy: Yes, PASS_MAX_DAYS is set to 90")
            else:
                # If PASS_MAX_DAYS is not 90, display its current value
                output.append(f"12. System Password Policy: Yes, PASS_MAX_DAYS is set to {pass_max_days}")
        except (IndexError, ValueError):
            output.append("12. System Password Policy: No, invalid format for PASS_MAX_DAYS")
      else:
        output.append("12. System Password Policy: No, unable to read PASS_MAX_DAYS")
    else:
      output.append("12. System Password Policy: No, not set and needs to be set")






    # # 15. Password Expiration Period
    # #expiration_period_status = run_command("grep '^PASS_MAX_DAYS' /etc/login.defs")
    # if expiration_period_status:
    #     output.append("15. Password Expiration Policy Set: Yes, it is set")
    # else:
    #     output.append("15. Password Expiration Policy Set: No, needs to set")

    # 13. System and Software Updates
    updates_status = run_command("sudo apt-get update && sudo apt-get upgrade -s")

    # Check if the output contains '0 upgraded'
    if updates_status and any("0 upgraded" in line for line in updates_status):
       output.append("13. System and Software Up-to-date: Yes, system is up-to-date")
    else:
       output.append("13. System and Software Up-to-date: No, system needs an update")

    # 14. Warning Banner at Login
    warning_banner_status = run_command("test -s /etc/motd && echo 'Yes' || echo 'No'")
    if "Yes" in warning_banner_status:
        output.append("14. Pre-login Warning Banner: Yes, it displays a warning banner")
    else:
        output.append("14. Pre-login Warning Banner: No, does not show warning banner")

    # 15. Post-login Warning Banner (SSH)
    post_warning_banner_status = run_command("grep -E '^[^#]*Banner' /etc/ssh/sshd_config")

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

    # 16. Logging Configuration (syslogd check)
    syslog_status, error = run_command("systemctl is-active syslog")

    # Check if the service is active by matching the exact "active" output from systemctl
    if syslog_status.strip() == "active":
      output.append("16. Syslog Installed and Active: Yes, it is installed and active")
    else:
      output.append("16. Syslog Installed and Active: No, it is not active or not installed")



    # 17. Disable SSH Root Login
    ssh_root_login_status, error = run_command("grep -E '^PermitRootLogin\\s+no$' /etc/ssh/sshd_config")

    # If `ssh_root_login_status` has content, it means PermitRootLogin is set to 'no'
    if ssh_root_login_status.strip():
      output.append("17. SSH Root Login Disabled: Yes, it is disabled")
    else:
      output.append("17. SSH Root Login Disabled: No, it is not disabled")


   
    # 18. Inactive Terminal Timeout
    inactive_timeout_status, error = run_command("grep -E '^[^#]*ClientAliveInterval' /etc/ssh/sshd_config")

   # Check if the output has an uncommented line with `ClientAliveInterval`
    if inactive_timeout_status.strip():
      output.append("18. Inactive Terminal Timeout is on: Yes, inactive terminal timeout is set.")
    else:
      output.append("18. Inactive Terminal Timeout is on: No, inactive terminal timeout needs to be set.")


    # 19. OSSEC HIDS Installed
    ossec_status = run_command("command -v ossec-control")

    # Check if ossec_status is a string and not empty
    if isinstance(ossec_status, str) and ossec_status.strip():  # Ensure it's a string and not empty
      output.append("19. OSSEC HIDS Installed: Yes, it is installed")
    else:
      output.append("19. OSSEC HIDS Installed: No, needs to be installed")



   # 20. Restrict SSH Access to Selected Users
    ssh_access_status = run_command("grep '^AllowUsers' /etc/ssh/sshd_config")

    # If the command found no output (i.e., the list is empty or contains no valid 'AllowUsers' lines)
    if ssh_access_status and len(ssh_access_status) > 0:
      output.append("20. SSH Access Restricted to Selected Users: No, SSH is not restricted to selected users")
    else:
      output.append("20. SSH Access Restricted to Selected Users: Yes, it is restricted to selected users")

    # 21. Network Time Protocol (NTP) Configured
    # Capture the full output from timedatectl
    ntp_status = run_command("timedatectl | grep 'NTP service: active'")

    
    if ntp_status :
      output.append("21. NTP Configured: Yes, system is synchronized using NTP")
    else:
      output.append("21. NTP Configured: No, system is not synchronized using NTP")


  # 22. rsyslog and Centralized Logging Configured
    rsyslog_status, error = run_command("systemctl is-active rsyslog")

    # Check if the service is active by matching the exact "active" output from systemctl
    if rsyslog_status.strip() == "active":
      output.append("22. rsyslog Installed and Active: Yes, it is installed and active")
    else:
      output.append("22. rsyslog Installed and Active: No, it is not active or not installed")


    # 23. IPv6 Disabled
    ipv6_status = run_command("sysctl net.ipv6.conf.all.disable_ipv6")

    # Since 'run_command' returns a list of lines, we need to check the first line for "1"
    if ipv6_status and "1" in ipv6_status[0]:
      output.append("23. IPv6 Disabled: Yes, IPv6 is disabled")
    else:
      output.append("23. IPv6 Disabled: No, IPv6 is not disabled")

   # 24. Password Hashing Algorithm (SHA-512)
    password_hashing_status, error = run_command("grep -E '^[^#]*ENCRYPT_METHOD SHA512' /etc/login.defs")

    # Check if the output has an uncommented line with `ENCRYPT_METHOD SHA512`
    if password_hashing_status.strip():
       output.append("24. Password Hashing Algorithm SHA-512: Yes, password hashing algorithm SHA-512 is set")
    else:
       output.append("24. Password Hashing Algorithm SHA-512: No, password hashing algorithm SHA-512 is not set")


    # # 28. Disable USB Access
    # usb_access_status = run_command("lsmod | grep usb_storage")
    # if usb_access_status:
    #     output.append("25. USB Access Disabled: No, it is not disabled")
    # else:
    #     output.append("25. USB Access Disabled: Yes, it is disabled")

   # 25. Single-User Mode Requires Authentication
    single_user_auth_status = run_command("sudo grep -r 'sulogin' /usr/share/initramfs-tools/scripts/")

   # Check if any valid output is found (i.e., 'sulogin' found in the files)
    if single_user_auth_status and len(single_user_auth_status) > 0:
      output.append("25. Single-User Mode Requires Authentication: No, it is not set")
    else:
      output.append("25. Single-User Mode Requires Authentication: Yes, it is set")

   # 26. SSH X11 Forwarding Disabled
    ssh_x11_forwarding_status, error = run_command("grep -E '^[^#]*X11Forwarding no' /etc/ssh/sshd_config")

   # Check if the command returns any output indicating X11 forwarding is disabled
    if ssh_x11_forwarding_status.strip():
      output.append("26. SSH X11 Forwarding Disabled: Yes, it is disabled")
    else:
      output.append("26. SSH X11 Forwarding Disabled: No, it is enabled")


    return render_template('index.html', output="\n".join(output))



if __name__ == '__main__':
    app.run(debug=True)
