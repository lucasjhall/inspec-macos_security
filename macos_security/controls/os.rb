control 'os_sshd_login_grace_time_configure' do
  title 'Set Login Grace Time to 30 or Less'
  desc     "
    If SSHD is enabled then it _MUST_ be configured to wait only 30 seconds before timing out logon attempts.
    NOTE: /etc/ssh/sshd_config will be automatically modified to its original state following any update or major upgrade to the operating system.
    "
  impact 0.5
  describe command("/usr/bin/grep -c \"^LoginGraceTime 30\" /etc/ssh/sshd_config")     do
    its('exit_status') { should eq 1 }
  end
end
control 'os_firewall_default_deny_require' do
  title 'Control Connections to Other Systems via a Deny-All and Allow-by-Exception Firewall Policy'
  desc     "
    A deny-all and allow-by-exception firewall policy _MUST_ be employed for managing connections to other systems. 
    Organizations _MUST_ ensure the built-in packet filter firewall is configured correctly to employ the default deny rule.
    Failure to restrict network connectivity to authorized systems permits inbound connections from malicious systems. It also permits outbound connections that may facilitate the exfiltration of data.
    If you are using a third-party firewall solution, this setting does not apply. 
    [IMPORTANT]
    ====
    Configuring the built-in packet filter firewall to employ the default deny rule has the potential to interfere with applications on the system in an unpredictable manner. Information System Security Officers (ISSOs) may make the risk-based decision not to configure the built-in packet filter firewall to employ the default deny rule to avoid losing functionality, but they are advised to first fully weigh the potential risks posed to their organization.
    ====
    "
  impact 0
  describe command("/sbin/pfctl -a '*' -sr &> /dev/null | /usr/bin/grep -c \"block drop in all\"")     do
    its('exit_status') { should eq 1 }
  end
end
control 'os_firmware_password_require' do
  title 'Enable Firmware Password'
  desc     "
    A firmware password _MUST_ be enabled and set. 
    Single user mode, recovery mode, the Startup Manager, and several other tools are available on macOS by holding the \"Option\" key down during startup. Setting a firmware password restricts access to these tools.
    To set a firmware passcode use the following command:
    [source,bash]
    ----
    /usr/sbin/firmwarepasswd -setpasswd
    ----
    NOTE: If firmware password or passcode is forgotten, the only way to reset the forgotten password is through the use of a machine specific binary generated and provided by Apple. Schedule a support call, and provide proof of purchase before the firmware binary will be generated.
    "
  impact 0.5
  describe command("/usr/sbin/firmwarepasswd -check | /usr/bin/grep -c \"Password Enabled: Yes\"")     do
    its('exit_status') { should eq 1 }
  end
end
control 'os_gatekeeper_rearm' do
  title 'Enforce Gatekeeper 30 Day Automatic Rearm'
  desc     "
    Gatekeeper _MUST_ be configured to automatically rearm after 30 days if disabled.
    "
  impact 0
  describe command("/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'GKAutoRearm = 1'")     do
    its('exit_status') { should eq 1 }
  end
end
control 'os_root_disable' do
  title 'Disable Root Login'
  desc     "
    To assure individual accountability and prevent unauthorized access, logging in as root at the login window _MUST_ be disabled.
    The macOS system _MUST_ require individuals to be authenticated with an individual authenticator prior to using a group authenticator, and administrator users _MUST_ never log in directly as root. 
    "
  impact 0
  describe command("/usr/bin/dscl . -read /Users/root UserShell 2>&1 | /usr/bin/grep -c \"/usr/bin/false\"")     do
    its('exit_status') { should eq 1 }
  end
end
control 'os_guest_account_disable' do
  title 'Disable the Guest Account'
  desc     "
    Guest access _MUST_ be disabled. 
    Turning off guest access prevents anonymous users from accessing files.
    "
  impact 1.0
  describe command("/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'DisableGuestAccount = 1'")     do
    its('exit_status') { should eq 1 }
  end
end
control 'os_policy_banner_ssh_enforce' do
  title 'Enforce SSH to Display Policy Banner'
  desc     "
    SSH _MUST_ be configured to display a policy banner. 
    Displaying a standardized and approved use notification before granting access to the operating system ensures that users are provided with privacy and security notification verbiage that is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.
    System use notifications are required only for access via login interfaces with human users and are not required when such human interfaces do not exist
    NOTE: /etc/ssh/sshd_config will be automatically modified to its original state following any update or major upgrade to the operating system.
    "
  impact 0.5
  describe command("/usr/bin/grep -c \"^Banner /etc/banner\" /etc/ssh/sshd_config")     do
    its('exit_status') { should eq 1 }
  end
end
control 'os_password_proximity_disable' do
  title 'Disable Proximity Based Password Sharing Requests'
  desc     "
    Proximity based password sharing requests _MUST_ be disabled. 
    The default behavior of macOS is to allow users to request passwords from other known devices (macOS and iOS). This feature _MUST_ be disabled to prevent passwords from being shared.
    "
  impact 0
  describe command("/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'allowPasswordProximityRequests = 0'")     do
    its('exit_status') { should eq 1 }
  end
end
control 'os_mdm_require' do
  title 'Enforce Enrollment in Mobile Device Management'
  desc     "
    You _MUST_ enroll your Mac in a Mobile Device Management (MDM) software.
    User Approved MDM (UAMDM) enrollment or enrollment via Apple Business Manager (ABM)/Apple School Manager (ASM) is required to manage certain security settings. Currently these include:
    * Allowed Kernel Extensions
    * Allowed Approved System Extensions
    * Privacy Preferences Policy Control Payload
    * ExtensibleSingleSignOn
    * FDEFileVault
    In macOS 11, UAMDM grants Supervised status on a Mac, unlocking the following MDM features, which were previously locked behind ABM:
    * Activation Lock Bypass
    * Access to Bootstrap Tokens
    * Scheduling Software Updates
    * Query list and delete local users
    "
  impact 0
  describe command("/usr/bin/profiles status -type enrollment | /usr/bin/awk -F: '/MDM enrollment/ {print $2}' | /usr/bin/grep -c \"Yes (User Approved)\"")     do
    its('exit_status') { should eq 1 }
  end
end
control 'os_screensaver_loginwindow_enforce' do
  title 'Enforce Screen Saver at Login Window'
  desc     "
    A default screen saver _MUST_ be configured to display at the login window and _MUST_ not display any sensitive information.
    "
  impact 0.1
  describe command("/usr/bin/profiles -P -o stdout  | /usr/bin/grep -c loginWindowModulePath")     do
    its('exit_status') { should eq 1 }
  end
end
control 'os_handoff_disable' do
  title 'Disable Handoff'
  desc     "
    Handoff _MUST_ be disabled. 
    Handoff allows you to continue working on a document or project when the user switches from one Apple device to another. Disabling Handoff prevents data transfers to unauthorized devices.
    "
  impact 0
  describe command("/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'allowActivityContinuation = 0'")     do
    its('exit_status') { should eq 1 }
  end
end
control 'os_sshd_key_exchange_algorithm_configure' do
  title 'Configure SSHD to Use Secure Key Exchange Algorithms'
  desc     "
    Unapproved mechanisms for authentication to the cryptographic module are not verified, and therefore cannot be relied upon to provide confidentiality or integrity, resulting in the compromise of DoD data.
    Operating systems using encryption are required to use FIPS-compliant mechanisms for authenticating to cryptographic modules.
    The implementation of OpenSSH that is included with macOS does not utilize a FIPS 140-2 validated cryptographic module. While the listed Key Exchange Algorithms are FIPS 140-2 approved, the module implementing them has not been validated.
    By specifying a Key Exchange Algorithm list with the order of hashes being in a “strongest to weakest” orientation, the system will automatically attempt to use the strongest Key Exchange Algorithm for securing SSH connections.
    NOTE: /etc/ssh/sshd_config will be automatically modified to its original state following any update or major upgrade to the operating system.
    "
  impact 0.5
  describe command("/usr/bin/grep -c \"^KexAlgorithms diffie-hellman-group-exchange-sha256\" /etc/ssh/sshd_config")     do
    its('exit_status') { should eq 1 }
  end
end
control 'os_firewall_log_enable' do
  title 'Enable Firewall Logging'
  desc     "
    Firewall logging _MUST_ be enabled. 
    Firewall logging ensures that malicious network activity will be logged to the system. 
    NOTE: The firewall data is logged to Apple's Unified Logging with the subsystem com.apple.alf and the data is marked as private.
    "
  impact 0
  describe command("/usr/libexec/ApplicationFirewall/socketfilterfw --getloggingmode | /usr/bin/grep -c \"Log mode is on\"")     do
    its('exit_status') { should eq 1 }
  end
end
control 'os_ssh_server_alive_interval_configure' do
  title 'Configure SSH ServerAliveInterval option set to 900 or less'
  desc     "
    SSH _MUST_ be configured with an Active Server Alive Maximum Count set to 900 or less. 
    Setting the Active Server Alive Maximum Count to 900 (second) will log users out after a 15-minute interval of inactivity.
    NOTE: /etc/ssh/ssh_config will be automatically modified to its original state following any update or major upgrade to the operating system.
    "
  impact 0
  describe command("/usr/bin/grep -c \"^ServerAliveInterval 900\" /etc/ssh/ssh_config")     do
    its('exit_status') { should eq 1 }
  end
end
control 'os_system_wide_preferences_configure' do
  title 'Require Administrator Password to Modify System-Wide Preferences'
  desc     "
    The system _MUST_ be configured to require an administrator password in order to modify the system-wide preferences in System Preferences. 
    Some Preference Panes in System Preferences contain settings that affect the entire system. Requiring a password to unlock these system-wide settings reduces the risk of a non-authorized user modifying system configurations.
    "
  impact 0.5
  describe command("/usr/bin/security authorizationdb read system.preferences 2> /dev/null |  /usr/bin/grep -A 1 \"<key>shared</key>\" | /usr/bin/grep -c \"<false/>\"")     do
    its('exit_status') { should eq 1 }
  end
end
control 'os_tftpd_disable' do
  title 'Disable Trivial File Tansfer Protocol Service'
  desc     "
    If the system does not require Trivial File Tansfer Protocol (TFTP), support it is non-essential and _MUST_ be disabled.
    The information system _MUST_ be configured to provide only essential capabilities. Disabling TFTP helps prevent the unauthorized connection of devices and the unauthorized transfer of information.  
    "
  impact 1.0
  describe command("/bin/launchctl print-disabled system | /usr/bin/grep -c '\"com.apple.tftpd\" => true'")     do
    its('exit_status') { should eq 1 }
  end
end
control 'os_password_autofill_disable' do
  title 'Disable Password Autofill'
  desc     "
    Password Autofill _MUST_ be disabled. 
    macOS allows users to save passwords and use the Password Autofill feature in Safari and compatible apps. To protect against malicious users gaining access to the system, this feature _MUST_ be disabled to prevent users from being prompted to save passwords in applications.
    "
  impact 0
  describe command("/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'allowPasswordAutoFill = 0'")     do
    its('exit_status') { should eq 1 }
  end
end
control 'os_sshd_client_alive_interval_configure' do
  title 'Configure SSHD ClientAliveInterval option set to 900 or less'
  desc     "
    If SSHD is enabled then it _MUST_ be configured with an Active Client Alive Maximum Count set to 900 or less. 
    Setting the Active Client Alive Maximum Count to 900 (second) will log users out after a 15-minute interval of inactivity.
    NOTE: /etc/ssh/sshd_config will be automatically modified to its original state following any update or major upgrade to the operating system.
    "
  impact 0.5
  describe command("/usr/bin/grep -c \"^ClientAliveInterval 900\" /etc/ssh/sshd_config")     do
    its('exit_status') { should eq 1 }
  end
end
control 'os_password_sharing_disable' do
  title 'Disable Password Sharing'
  desc     "
    Password Sharing _MUST_ be disabled. 
    The default behavior of macOS is to allow users to share a password over Airdrop between other macOS and iOS devices. This feature _MUST_ be disabled to prevent passwords from being shared.
    "
  impact 0
  describe command("/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'allowPasswordSharing = 0'")     do
    its('exit_status') { should eq 1 }
  end
end
control 'os_ssh_fips_140_ciphers' do
  title 'Limit SSH to FIPS 140 Validated Ciphers'
  desc     "
    SSH _MUST_ be configured to limit the ciphers to algorithms that are FIPS 140 validated.
    FIPS 140-2 is the current standard for validating that mechanisms used to access cryptographic modules utilize authentication that meet federal requirements.
    Operating systems utilizing encryption _MUST_ use FIPS validated mechanisms for authenticating to cryptographic modules. 
    NOTE: /etc/ssh/ssh_config will be automatically modified to its original state following any update or major upgrade to the operating system.
    "
  impact 0
  describe command("/usr/bin/grep -c \"^Ciphers aes256-ctr,aes192-ctr,aes128-ctr\" /etc/ssh/ssh_config")     do
    its('exit_status') { should eq 1 }
  end
end
control 'os_authenticated_root_enable' do
  title 'Enable Authenticated Root'
  desc     "
    Authenticated Root _MUST_ be enabled.
    When Authenticated Root is enabled the macOS is booted from a signed volume that is cryptographically protected to prevent tampering with the system volume."
  impact 0
  describe command("/usr/bin/csrutil authenticated-root | /usr/bin/grep -c 'enabled'")     do
    its('exit_status') { should eq 1 }
  end
end
control 'os_sshd_client_alive_count_max_configure' do
  title 'Set SSHD Active Client Alive Maximum to Zero'
  desc     "
    If SSHD is enabled it _MUST_ be configured with an Active Client Alive Maximum Count set to zero. Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session or an incomplete login attempt will also free up resources committed by the managed network element.
    NOTE: /etc/ssh/sshd_config will be automatically modified to its original state following any update or major upgrade to the operating system.
    "
  impact 0.5
  describe command("/usr/bin/grep -c \"^ClientAliveCountMax 0\" /etc/ssh/sshd_config")     do
    its('exit_status') { should eq 1 }
  end
end
control 'os_privacy_setup_prompt_disable' do
  title 'Disable Privacy Setup Services During Setup Assistant'
  desc     "
    The prompt for Privacy Setup services during Setup Assistant _MUST_ be disabled.
    Organizations _MUST_ apply organization-wide configuration settings. The macOS Privacy Setup services prompt guides new users through enabling their own specific privacy settings; this is not essential and, therefore, _MUST_ be disabled to prevent against the risk of individuals electing privacy settings with the potential to override organization-wide settings.
    "
  impact 0.5
  describe command("/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'SkipPrivacySetup = 1'")     do
    its('exit_status') { should eq 1 }
  end
end
control 'os_secure_boot_verify' do
  title 'Ensure Secure Boot Level Set to Full'
  desc     "
    The Secure Boot security setting _MUST_ be set to full.
    Full security is the default Secure Boot setting in macOS. During startup, when Secure Boot is set to full security, the Mac will verify the integrity of the operating system before allowing the operating system to boot. 
    Note: This will only return a proper result on a T2 Mac
    "
  impact 0
  describe command("/usr/libexec/mdmclient QuerySecurityInfo | /usr/bin/grep -c \"SecureBootLevel = full\"")     do
    its('exit_status') { should eq 1 }
  end
end
control 'os_sudoers_tty_configure' do
  title 'Configure Sudoers to Authenticate Users on a Per -tty Basis'
  desc     "
    The file /etc/sudoers _MUST_ be configured to include tty_tickets.
    This rule ensures that the \"sudo\" command will prompt for the administrator’s password at least once in each newly opened terminal window. This prevents a malicious user from taking advantage of an unlocked computer or an abandoned logon session by bypassing the normal password prompt requirement. Without the \"tty_tickets\" option, all open local and remote logon sessions would be authenticated to use sudo without a password for the duration of the configured password timeout window.
    "
  impact 1.0
  describe command("/usr/bin/grep -Ec \"^Defaults tty_tickets\" /etc/sudoers")     do
    its('exit_status') { should eq 1 }
  end
end
control 'os_uucp_disable' do
  title 'Disable Unix-to-Unix Copy Protocol Service'
  desc     "
    The system _MUST_ not have the Unix-to-Unix Copy Protocol (UUCP) service active.
    UUCP, a set of programs that enable the sending of files between different UNIX systems as well as sending commands to be executed on another system, is not essential and _MUST_ be disabled in order to prevent the unauthorized connection of devices, transfer of information, and tunneling. 
    "
  impact 0.5
  describe command("/bin/launchctl print-disabled system | /usr/bin/grep -c '\"com.apple.uucp\" => true'")     do
    its('exit_status') { should eq 1 }
  end
end
control 'os_policy_banner_loginwindow_enforce' do
  title 'Display Policy Banner at Login Window'
  desc     "
    Displaying a standardized and approved use notification before granting access to the operating system ensures that users are provided with privacy and security notification verbiage that is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.
    System use notifications are required only for access via login interfaces with human users and are not required when such human interfaces do not exist.
    The policy banner will show if a \"PolicyBanner.rtf\" or \"PolicyBanner.rtfd\" exists in the \"/Library/Security\" folder.
    NOTE: 
      The banner text of the document _MUST_ read:
      \"You are accessing a U.S. Government information system, which includes: 1) this computer, 2) this computer network, 3) all Government-furnished computers connected to this network, and 4) all Government-furnished devices and storage media attached to this network or to a computer on this network. You understand and consent to the following: you may access this information system for authorized use only; unauthorized use of the system is prohibited and subject to criminal and civil penalties; you have no reasonable expectation of privacy regarding any communication or data transiting or stored on this information system at any time and for any lawful Government purpose, the Government may monitor, intercept, audit, and search and seize any communication or data transiting or stored on this information system; and any communications or data transiting or stored on this information system may be disclosed or used for any lawful Government purpose. This information system may contain Controlled Unclassified Information (CUI) that is subject to safeguarding or dissemination controls in accordance with law, regulation, or Government-wide policy. Accessing and using this system indicates your understanding of this warning.\"
    "
  impact 0.5
  describe command("/bin/ls -ld /Library/Security/PolicyBanner.rtf* | /usr/bin/wc -l | tr -d ' '")     do
    its('exit_status') { should eq 1 }
  end
end
control 'os_user_app_installation_prohibit' do
  title 'Prohibit User Installation of Software into /Users/'
  desc     "
    Users _MUST_ not be allowed to install software into /Users/. 
    Allowing regular users to install software, without explicit privileges, presents the risk of untested and potentially malicious software being installed on the system. Explicit privileges (escalated or administrative privileges) provide the regular user with explicit capabilities and control that exceeds the rights of a regular user.
    "
  impact 0.5
  describe command("/usr/bin/profiles -P -o stdout-xml | /usr/bin/sed -n '/pathBlackList/,/key/p' | /usr/bin/grep -c \"/Users/\"")     do
    its('exit_status') { should eq 1 }
  end
end
control 'os_touchid_prompt_disable' do
  title 'Disable TouchID Prompt during Setup Assistant'
  desc     "
    The prompt for TouchID during Setup Assistant _MUST_ be disabled.
    macOS prompts new users through enabling TouchID during Setup Assistant; this is not essential and, therefore, _MUST_ be disabled to prevent against the risk of individuals electing to enable TouchID to override organization-wide settings.
    "
  impact 0
  describe command("/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'SkipTouchIDSetup = 1'")     do
    its('exit_status') { should eq 1 }
  end
end
control 'os_filevault_autologin_disable' do
  title 'Disable FileVault Automatic Login'
  desc     "
    If FileVault is enabled, automatic login _MUST_ be disabled, so that both FileVault and login window authentication are required.
    The default behavior of macOS when FileVault is enabled is to automatically log in to the computer once successfully passing your FileVault credentials. 
    "
  impact 0.5
  describe command("/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'DisableFDEAutoLogin = 1'")     do
    its('exit_status') { should eq 1 }
  end
end
control 'os_messages_app_disable' do
  title 'Disable Messages App'
  desc     "
    The macOS built-in Messages.app _MUST_ be disabled. 
    The Messages.app establishes a connection to Apple’s iCloud service, even when security controls to disable iCloud access have been put in place. 
    "
  impact 0.1
  describe command("/usr/bin/profiles -P -o stdout | /usr/bin/grep -A 20 familyControlsEnabled | /usr/bin/grep -c \"/Applications/Messages.app\"")     do
    its('exit_status') { should eq 1 }
  end
end
control 'os_airdrop_disable' do
  title 'Disable AirDrop'
  desc     "
    AirDrop _MUST_ be disabled to prevent file transfers to or from unauthorized devices.
    AirDrop allows users to share and receive files from other nearby Apple devices."
  impact 0.5
  describe command("/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'DisableAirDrop = 1'")     do
    its('exit_status') { should eq 1 }
  end
end
control 'os_parental_controls_enable' do
  title 'Enable Parental Controls'
  desc     "
    Parental Controls _MUST_ be enabled. 
    Control of program execution is a mechanism used to prevent program execution of unauthorized programs, which is critical to maintaining a secure system baseline.
    Parental Controls on the macOS consist of many different payloads, which are set individually depending on the type of control required. Enabling parental controls allows for further configuration of these restrictions.
    "
  impact 0
  describe command("/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'familyControlsEnabled = 1'")     do
    its('exit_status') { should eq 1 }
  end
end
control 'os_system_read_only' do
  title 'Ensure System Volume is Read Only'
  desc     "
    The System volume _MUST_ be mounted as read-only in order to ensure that configurations critical to the integrity of the macOS have not been compromised. System Integrity Protection (SIP) will prevent the system volume from being mounted as writable.
    "
  impact 0
  describe command("/usr/sbin/system_profiler SPStorageDataType | /usr/bin/awk '/Mount Point: /$/{x=NR+2}(NR==x){print $2}'")     do
    its('stdout') { should match(/No/) }
  end
end
control 'os_ssh_server_alive_count_max_configure' do
  title 'Set SSH Active Server Alive Maximum to Zero'
  desc     "
    SSH _MUST_ be configured with an Active Server Alive Maximum Count set to zero. Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session or an incomplete login attempt will also free up resources committed by the managed network element.
    NOTE: /etc/ssh/ssh_config will be automatically modified to its original state following any update or major upgrade to the operating system.
    "
  impact 0
  describe command("/usr/bin/grep -c \"^ServerAliveCountMax 0\" /etc/ssh/ssh_config")     do
    its('exit_status') { should eq 1 }
  end
end
control 'os_nfsd_disable' do
  title 'Disable Network File System Service'
  desc     "
    Support for Network File Systems (NFS) services is non-essential and, therefore, _MUST_ be disabled.
    "
  impact 0.5
  describe command("/bin/launchctl print-disabled system | /usr/bin/grep -c '\"com.apple.nfsd\" => true'")     do
    its('exit_status') { should eq 1 }
  end
end
control 'os_sshd_permit_root_login_configure' do
  title 'Disable Root Login for SSH'
  desc     "
    If SSH is enabled to assure individual accountability and prevent unauthorized access, logging in as root via SSH _MUST_ be disabled. 
    The macOS system MUST  require individuals to be authenticated with an individual authenticator prior to using a group authenticator, and administrator users _MUST_ never log in directly as root. 
    NOTE: /etc/ssh/sshd_config will be automatically modified to its original state following any update or major upgrade to the operating system.
    "
  impact 0.5
  describe command("/usr/bin/grep -c \"^PermitRootLogin no\" /etc/ssh/sshd_config")     do
    its('exit_status') { should eq 1 }
  end
end
control 'os_httpd_disable' do
  title 'Disable the Built-in Web Server'
  desc     "
    The built-in web server is a non-essential service built into macOS and _MUST_ be disabled."
  impact 0.5
  describe command("/bin/launchctl print-disabled system | /usr/bin/grep -c '\"org.apache.httpd\" => true'")     do
    its('exit_status') { should eq 1 }
  end
end
control 'os_gatekeeper_enable' do
  title 'Enable Gatekeeper'
  desc     "
    Gatekeeper _MUST_ be enabled. 
    Gatekeeper is a security feature that ensures that applications are digitally signed by an Apple-issued certificate before they are permitted to run. Digital signatures allow the macOS host to verify that the application has not been modified by a malicious third party.
    Administrator users will still have the option to override these settings on a case-by-case basis.
    "
  impact 1.0
  describe command("/usr/sbin/spctl --status | /usr/bin/grep -c \"assessments enabled\"")     do
    its('exit_status') { should eq 1 }
  end
end
control 'os_sip_enable' do
  title 'Ensure System Integrity Protection is Enabled'
  desc     "
    System Integrity Protection (SIP) _MUST_ be enabled. 
    SIP is vital to protecting the integrity of the system as it prevents malicious users and software from making unauthorized and/or unintended modifications to protected files and folders; ensures the presence of an audit record generation capability for defined auditable events for all operating system components; protects audit tools from unauthorized access, modification, and deletion; restricts the root user account and limits the actions that the root user can perform on protected parts of the macOS; and prevents non-privileged users from granting other users direct access to the contents of their home directories and folders.
    "
  impact 0.5
  describe command("/usr/bin/csrutil status | /usr/bin/grep -c 'System Integrity Protection status: enabled.'")     do
    its('exit_status') { should eq 1 }
  end
end
control 'os_removable_media_disable' do
  title 'Disable Removable Storage Devices'
  desc     "
    Removable media, such as USB connected external hard drives, thumb drives, and optical media, _MUST_ be disabled for users.
    Disabling removable storage devices reduces the risks and known vulnerabilities of such devices (e.g., malicious code insertion)
    [IMPORTANT]
    ====
    Some organizations rely on the use of removable media for storing and sharing data. Information System Security Officers (ISSOs) may make the risk-based decision not to disable external hard drives to avoid losing this functionality, but they are advised to first fully weigh the potential risks posed to their organization.
    ====
    "
  impact 0
  describe command("/usr/bin/profiles -P -o stdout | /usr/bin/grep 'harddisk-external' -A3 | /usr/bin/grep -Ec \"eject|alert\"")     do
    its('exit_status') { should eq 2 }
  end
end
control 'os_guest_access_smb_disable' do
  title 'Disable Guest Access to Shared SMB Folders'
  desc     "
    Guest access to shared Server Message Block (SMB) folders _MUST_ be disabled. 
    Turning off guest access prevents anonymous users from accessing files shared via SMB.
    "
  impact 0
  describe command("/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'AllowGuestAccess = 0'")     do
    its('exit_status') { should eq 1 }
  end
end
control 'os_policy_banner_ssh_configure' do
  title 'Display Policy Banner at Remote Login'
  desc     "
    Remote login service _MUST_ be configured to display a policy banner at login. 
    Displaying a standardized and approved use notification before granting access to the operating system ensures that users are provided with privacy and security notification verbiage that is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.
    System use notifications are required only for access via login interfaces with human users and are not required when such human interfaces do not exist.
    "
  impact 0.5
  describe command("bannerText=\"You are accessing a U.S. Government information system, which includes: 1) this computer, 2) this computer network, 3) all Government-furnished computers connected to this network, and 4) all Government-furnished devices and storage media attached to this network or to a computer on this network. You understand and consent to the following: you may access this information system for authorized use only; unauthorized use of the system is prohibited and subject to criminal and civil penalties; you have no reasonable expectation of privacy regarding any communication or data transiting or stored on this information system at any time and for any lawful Government purpose, the Government may monitor, intercept, audit, and search and seize any communication or data transiting or stored on this information system; and any communications or data transiting or stored on this information system may be disclosed or used for any lawful Government purpose. This information system may contain Controlled Unclassified Information (CUI) that is subject to safeguarding or dissemination controls in accordance with law, regulation, or Government-wide policy. Accessing and using this system indicates your understanding of this warning.\"
/usr/bin/grep -c \"$bannerText\" /etc/banner")     do
    its('exit_status') { should eq 1 }
  end
end
control 'os_time_server_enabled' do
  title 'Enable Time Synchronization Daemon'
  desc     "
    The macOS time synchronization daemon (timed) _MUST_ be enabled for proper time synchronization to an authorized time server.
    "
  impact 0.5
  describe command("/bin/launchctl list | /usr/bin/grep -c com.apple.timed")     do
    its('exit_status') { should eq 1 }
  end
end
control 'os_unlock_active_user_session_disable' do
  title 'Disable Login to Other User’s Active and Locked Sessions'
  desc     "
    The ability to log in to another user’s active or locked session _MUST_ be disabled. 
    macOS has a privilege that can be granted to any user that will allow that user to unlock active user’s sessions. Disabling the admins and/or user’s ability to log into another user’s active andlocked session prevents unauthorized persons from viewing potentially sensitive and/or personal information.
    "
  impact 0
  describe command("/usr/bin/security authorizationdb read system.login.screensaver 2>&1 | /usr/bin/grep -c 'use-login-window-ui'")     do
    its('exit_status') { should eq 1 }
  end
end
control 'os_internet_accounts_prefpane_disable' do
  title 'Disable the Internet Accounts System Preference Pane'
  desc     "
    The Internet Accounts System Preference pane _MUST_ be disabled to prevent the addition of unauthorized internet accounts.
    [IMPORTANT]
    ====
    Some organizations may allow the use and configuration of the built-in Mail.app, Calendar.app, and Contacts.app for organizational communication. Information System Security Officers (ISSOs) may make the risk-based decision not to disable the Internet Accounts System Preference pane to avoid losing this functionality, but they are advised to first fully weigh the potential risks posed to their organization.
    ====
    "
  impact 0.5
  describe command("/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'com.apple.preferences.internetaccounts'")     do
    its('exit_status') { should eq 1 }
  end
end
control 'os_siri_prompt_disable' do
  title 'Disable Siri Setup during Setup Assistant'
  desc     "
    The prompt for Siri during Setup Assistant _MUST_ be disabled.
    Organizations _MUST_ apply organization-wide configuration settings. The macOS Siri Assistant Setup prompt guides new users through enabling their own specific Siri settings; this is not essential and, therefore, _MUST_ be disabled to prevent against the risk of individuals electing Siri settings with the potential to override organization-wide settings.
    "
  impact 0.5
  describe command("/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'SkipSiriSetup = 1'")     do
    its('exit_status') { should eq 1 }
  end
end
control 'os_appleid_prompt_disable' do
  title 'Disable Apple ID Setup during Setup Assistant'
  desc     "
    The prompt for Apple ID setup during Setup Assistant _MUST_ be disabled. 
    macOS will automatically prompt new users to set up an Apple ID while they are going through Setup Assistant if this is not disabled, misleading new users to think they need to create Apple ID accounts upon their first login.
    "
  impact 0.5
  describe command("/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'SkipCloudSetup = 1'")     do
    its('exit_status') { should eq 1 }
  end
end
control 'os_sshd_fips_140_ciphers' do
  title 'Limit SSHD to FIPS 140 Validated Ciphers'
  desc     "
    If SSHD is enabled then it _MUST_ be configured to limit the ciphers to algorithms that are FIPS 140 validated.
    FIPS 140-2 is the current standard for validating that mechanisms used to access cryptographic modules utilize authentication that meet federal requirements.
    Operating systems utilizing encryption _MUST_ use FIPS validated mechanisms for authenticating to cryptographic modules. 
    NOTE: /etc/ssh/sshd_config will be a
    "
  impact 0.5
  describe command("/usr/bin/grep -c \"^Ciphers aes256-ctr,aes192-ctr,aes128-ctr\" /etc/ssh/sshd_config")     do
    its('exit_status') { should eq 1 }
  end
end
control 'os_sshd_fips_140_macs' do
  title 'Limit SSHD to FIPS 140 Validated Message Authentication Code Algorithms'
  desc     "
    If SSHD is enabled then it _MUST_ be configured to limit the Message Authentication Codes (MACs) to algorithms that are FIPS 140 validated.
    FIPS 140-2 is the current standard for validating that mechanisms used to access cryptographic modules utilize authentication that meets federal requirements.
    Operating systems utilizing encryption _MUST_ use FIPS validated mechanisms for authenticating to cryptographic modules. 
    NOTE: /etc/ssh/sshd_config will be automatically modified to its original state following any update or major upgrade to the operating system.
    "
  impact 0.5
  describe command("/usr/bin/grep -c \"^MACs hmac-sha2-256,hmac-sha2-512\" /etc/ssh/sshd_config")     do
    its('exit_status') { should eq 1 }
  end
end
control 'os_certificate_authority_trust' do
  title 'Issue or Obtain Public Key Certificates from an Approved Service Provider'
  desc     "
    The organization _MUST_ issue or obtain public key certificates from an organization-approved service provider and ensure only approved trust anchors are in the System Keychain.
    "
  impact 1.0
  describe command("/usr/bin/security dump-keychain /Library/Keychains/System.keychain | /usr/bin/grep labl | awk -F'\"' '{ print $4 }'")     do
    its('stdout') { should match(/a list containing approved root certificates/) }
  end
end
control 'os_ssh_fips_140_macs' do
  title 'Limit SSH to FIPS 140 Validated Message Authentication Code Algorithms'
  desc     "
    SSH _MUST_ be configured to limit the Message Authentication Codes (MACs) to algorithms that are FIPS 140 validated.
    FIPS 140-2 is the current standard for validating that mechanisms used to access cryptographic modules utilize authentication that meets federal requirements.
    Operating systems utilizing encryption _MUST_ use FIPS validated mechanisms for authenticating to cryptographic modules. 
    NOTE: /etc/ssh/ssh_config will be automatically modified to its original state following any update or major upgrade to the operating system.
    "
  impact 0.5
  describe command("/usr/bin/grep -c \"^MACs hmac-sha2-256,hmac-sha2-512\" /etc/ssh/ssh_config")     do
    its('exit_status') { should eq 1 }
  end
end
control 'os_home_folders_secure' do
  title 'Secure User\'s Home Folders'
  desc     "
    The system _MUST_ be configured to prevent access to other users’ home folders.
    The default behavior of macOS is to allow all valid users access to the the top level of every other user’s home folder while restricting access only to the Apple default folders within. 
    "
  impact 0.5
  describe command("/usr/bin/find /System/Volumes/Data/Users -mindepth 1 -maxdepth 1 -type d -perm -1 | /usr/bin/grep -v \"Shared\" | /usr/bin/grep -v \"Guest\" | /usr/bin/wc -l | /usr/bin/xargs")     do
    its('exit_status') { should eq 0 }
  end
end
control 'os_facetime_app_disable' do
  title 'Disable FaceTime.app'
  desc     "
    The macOS built-in FaceTime.app _MUST_ be disabled. 
    The FaceTime.app establishes a connection to Apple’s iCloud service, even when security controls have been put in place to disable iCloud access. 
    "
  impact 0.1
  describe command("/usr/bin/profiles -P -o stdout | /usr/bin/grep -A 20 familyControlsEnabled | /usr/bin/grep -c \"/Applications/FaceTime.app\"")     do
    its('exit_status') { should eq 1 }
  end
end
control 'os_camera_disable' do
  title 'Disable Camera'
  desc     "
    macOS _MUST_ be configured to disable the camera.
    "
  impact 0.5
  describe command("/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'allowCamera = 0'")     do
    its('exit_status') { should eq 1 }
  end
end
control 'os_icloud_storage_prompt_disable' do
  title 'Disable iCloud Storage Setup during Setup Assistant'
  desc     "
    The prompt to set up iCloud storage services during Setup Assistant _MUST_ be disabled.
    The default behavior of macOS is to prompt new users to set up storage in iCloud. Disabling the iCloud storage setup prompt provides organizations more control over the storage of their data. 
    "
  impact 0.5
  describe command("/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'SkipiCloudStorageSetup = 1'")     do
    its('exit_status') { should eq 1 }
  end
end
control 'os_ir_support_disable' do
  title 'Disable Infrared (IR) support'
  desc     "
    Infrared (IR) support _MUST_ be disabled to prevent users from controlling the system with IR devices. 
    By default, if IR is enabled, the system will accept IR control from any remote device. 
    Note: This is applicable only to models of Mac Mini systems earlier than Mac Mini8,1.
    "
  impact 0
  describe command("/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'DeviceEnabled = 0'")     do
    its('exit_status') { should eq 1 }
  end
end
control 'os_mail_app_disable' do
  title 'Disable Mail App'
  desc     "
    The macOS built-in Mail.app _MUST_ be disabled. 
    The Mail.app contains functionality that can establish connections to Apple’s iCloud, even when security controls to disable iCloud access have been put in place.
    [IMPORTANT]
    ====
    Some organizations allow the use of the built-in Mail.app for organizational communication. Information System Security Officers (ISSOs) may make the risk-based decision not to disable the macOS built-in Mail.app to avoid losing this functionality, but they are advised to first fully weigh the potential risks posed to their organization.
    ====
    "
  impact 0.5
  describe command("/usr/bin/profiles -P -o stdout | /usr/bin/grep -A 20 familyControlsEnabled | /usr/bin/grep -c \"/Applications/Mail.app\"")     do
    its('exit_status') { should eq 1 }
  end
end
control 'os_bonjour_disable' do
  title 'Disable Bonjour Multicast'
  desc     "
    Bonjour multicast advertising _MUST_ be disabled to prevent the system from broadcasting its presence and available services over network interfaces.
    "
  impact 0.5
  describe command("/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'NoMulticastAdvertisements = 1'")     do
    its('exit_status') { should eq 1 }
  end
end
control 'os_calendar_app_disable' do
  title 'Disable Calendar.app'
  desc     "
    The macOS built-in Calendar.app _MUST_ be disabled as this application can establish a connection to non-approved services. This rule is in place to prevent inadvertent data transfers.
    [IMPORTANT]
    ====
    Some organizations allow the use of the built-in Calendar.app for organizational communication. Information System Security Officers (ISSOs) may make the risk-based decision not to disable the macOS built-in Mail.app to avoid losing this functionality, but they are advised to first fully weigh the potential risks posed to their organization.
    ====
    "
  impact 0.5
  describe command("/usr/bin/profiles -P -o stdout | /usr/bin/grep -A 20 familyControlsEnabled | /usr/bin/grep -c \"/Applications/Calendar.app\"")     do
    its('exit_status') { should eq 1 }
  end
end
control 'icloud_photos_disable' do
  title 'Disable iCloud Photo Library'
  desc     "
    The macOS built-in Photos.app connection to Apple’s iCloud service _MUST_ be disabled. 
    Apple’s iCloud service does not provide an organization with enough control over the storage and access of data and, therefore, automated photo synchronization _MUST_ be controlled by an organization approved service. 
    "
  impact 0.5
  describe command("/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'allowCloudPhotoLibrary = 0'")     do
    its('exit_status') { should eq 1 }
  end
end
