control 'sysprefs_automatic_logout_enforce' do
  title 'Enforce Auto Logout After 24 Hours of Inactivity'
  desc     "
    Auto logout _MUST_ be configured to automatically terminate a user session and log out the after 86400 seconds (24 hours) of inactivity. 
    NOTE:The maximum that macOS can be configured for autologoff is 86400 seconds (24 hours).
    [IMPORTANT]
    ====
    The 24-hour automatic logout may cause disruptions to an organization’s workflow and/or loss of data. Information System Security Officers (ISSOs) are advised to first fully weigh the potential risks posed to their organization before opting to disable the 24-hour automatic logout setting.
    ====
    "
  impact 0
  describe command("/usr/bin/profiles -P -o stdout | /usr/bin/grep -c '\"com.apple.autologout.AutoLogOutDelay\" = 86400'")     do
    its('exit_status') { should eq 0 }
  end
end
control 'sysprefs_smbd_disable' do
  title 'Disable Server Message Block Sharing'
  desc     "
    Support for Server Message Block (SMB) file sharing is non-essential and _MUST_ be disabled.
    The information system _MUST_ be configured to provide only essential capabilities.
    "
  impact 0.5
  describe command("/bin/launchctl print-disabled system | /usr/bin/grep -c '\"com.apple.smbd\" => true'")     do
    its('exit_status') { should eq 1 }
  end
end
control 'sysprefs_firewall_stealth_mode_enable' do
  title 'Enable Firewall Stealth Mode'
  desc     "
    Firewall Stealth Mode _MUST_ be enabled. 
    When stealth mode is enabled, the Mac will not respond to any probing requests, and only requests from authorized applications will still be authorized.
    [IMPORTANT]
    ====
    Enabling firewall stealth mode may prevent certain remote mechanisms used for maintenance and compliance scanning from properly functioning. Information System Security Officers (ISSOs) are advised to first fully weigh the potential risks posed to their organization before opting not to enable stealth mode.
    ====
    "
  impact 0.5
  describe command("/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode | /usr/bin/grep -c \"Stealth mode enabled\"")     do
    its('exit_status') { should eq 1 }
  end
end
control 'sysprefs_internet_sharing_disable' do
  title 'Disable Internet Sharing'
  desc     "
    If the system does not require Internet sharing, support for it is non-essential and _MUST_ be disabled.
    The information system _MUST_ be configured to provide only essential capabilities. Disabling Internet sharing helps prevent the unauthorized connection of devices, unauthorized transfer of information, and unauthorized tunneling.
    "
  impact 0.5
  describe command("/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'forceInternetSharingOff = 1'")     do
    its('exit_status') { should eq 1 }
  end
end
control 'sysprefs_rae_disable' do
  title 'Disable Remote Apple Events'
  desc     "
    If the system does not require Remote Apple Events, support for Apple Remote Events is non-essential and _MUST_ be disabled.
    The information system _MUST_ be configured to provide only essential capabilities. Disabling Remote Apple Events helps prevent the unauthorized connection of devices, the unauthorized transfer of information, and unauthorized tunneling. 
    "
  impact 0.5
  describe command("/bin/launchctl print-disabled system | /usr/bin/grep -c '\"com.apple.AEServer\" => true'")     do
    its('exit_status') { should eq 1 }
  end
end
control 'sysprefs_personalized_advertising_disable' do
  title 'Disable Personalized Advertising'
  desc     "
    Ad tracking and targeted ads _MUST_ be disabled.
    The information system _MUST_ be configured to provide only essential capabilities. Disabling ad tracking ensures that applications and advertisers are unable to track users’ interests and deliver targeted advertisements.  
    "
  impact 0
  describe command("/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'allowApplePersonalizedAdvertising = 0;'")     do
    its('exit_status') { should eq 1 }
  end
end
control 'sysprefs_ssh_enable' do
  title 'Enable SSH Server for Remote Access Sessions'
  desc     "
    Remote access sessions _MUST_ use encrypted methods to protect unauthorized individuals from gaining access. 
    "
  impact 0
  describe command("/bin/launchctl print-disabled system | /usr/bin/grep -c '\"com.openssh.sshd\" => true'")     do
    its('exit_status') { should eq 1 }
  end
end
control 'sysprefs_media_sharing_disabled' do
  title 'Disable Media Sharing'
  desc     "
    Media sharing _MUST_ be disabled.
    When Media Sharing is enabled, the computer starts a network listening service that shares the contents of the user’s music collection with other users in the same subnet. 
    The information system _MUST_ be configured to provide only essential capabilities. Disabling Media Sharing helps prevent the unauthorized connection of devices and the unauthorized transfer of information. Disabling Media Sharing mitigates this risk.
    NOTE: The Media Sharing preference panel will still allow \"Home Sharing\" and \"Share media with guests\" to be checked but the service will not be enabled.
    "
  impact 0
  describe command("/usr/bin/profiles -P -o stdout | /usr/bin/grep -Ec '(homeSharingUIStatus = 0|legacySharingUIStatus = 0|mediaSharingUIStatus = 1)'")     do
    its('exit_status') { should eq 1 }
  end
end
control 'sysprefs_ssh_disable' do
  title 'Disable SSH Server for Remote Access Sessions'
  desc     "
    SSH service _MUST_ be disabled for remote access.
    Remote access sessions _MUST_ use FIPS validated encrypted methods to protect unauthorized individuals from gaining access. 
    "
  impact 0.5
  describe command("/bin/launchctl print-disabled system | /usr/bin/grep -c '\"com.openssh.sshd\" => true'")     do
    its('exit_status') { should eq 1 }
  end
end
control 'sysprefs_screensaver_password_enforce' do
  title 'Enforce Screen Saver Password'
  desc     "
    Users _MUST_ authenticate when unlocking the screen saver. 
    The screen saver acts as a session lock and prevents unauthorized users from accessing the current user’s account.
    "
  impact 0.5
  describe command("/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'askForPassword = 1'")     do
    its('exit_status') { should eq 1 }
  end
end
control 'sysprefs_gatekeeper_identified_developers_allowed' do
  title 'Apply Gatekeeper Settings to Block Applications from Unidentified Developers'
  desc     "
    The information system implements cryptographic mechanisms to authenticate software prior to installation.
    Gatekeeper settings must be configured correctly to only allow the system to run applications downloaded from the Mac App Store or applications signed with a valid Apple Developer ID code. Administrator users will still have the option to override these settings on a per-app basis. Gatekeeper is a security feature that ensures that applications must be digitally signed by an Apple-issued certificate in order to run. Digital signatures allow the macOS to verify that the application has not been modified by a malicious third party.
    "
  impact 0.5
  describe command("/usr/sbin/spctl --status --verbose | /usr/bin/grep -c \"developer id enabled\"")     do
    its('exit_status') { should eq 1 }
  end
end
control 'sysprefs_gatekeeper_override_disallow' do
  title 'Configure Gatekeeper to Disallow End User Override'
  desc     "
    Gatekeeper _MUST_ be configured with a configuration profile to prevent normal users from overriding its settings. 
    If users are allowed to disable Gatekeeper or set it to a less restrictive setting, malware could be introduced into the system. 
    "
  impact 0.5
  describe command("/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'DisableOverride = 1'")     do
    its('exit_status') { should eq 1 }
  end
end
control 'sysprefs_screensaver_timeout_enforce' do
  title 'Enforce Screen Saver Timeout'
  desc     "
    The screen saver timeout _MUST_ be set to 15 minutes. 
    This rule ensures that a full session lock is triggered after 15 minutes of inactivity.
    "
  impact 0.5
  describe command("/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'idleTime = 900'")     do
    its('exit_status') { should eq 1 }
  end
end
control 'sysprefs_firewall_enable' do
  title 'Enable macOS Application Firewall'
  desc     "
    The macOS Application Firewall is the built-in firewall that comes with macOS, and it _MUST_ be enabled. 
    When the macOS Application Firewall is enabled, the flow of information within the information system and between interconnected systems will be controlled by approved authorizations.
    "
  impact 0.5
  describe command("/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate | /usr/bin/grep -c \"Firewall is enabled\"")     do
    its('exit_status') { should eq 1 }
  end
end
control 'sysprefs_find_my_disable' do
  title 'Disable Find My Service'
  desc     "
    The Find My service _MUST_ be disabled.
    A Mobile Device Management (MDM) solution _MUST_ be used to carry out remote locking and wiping instead of Apple’s Find My service.
    Apple’s Find My service uses a personal AppleID for authentication. Organizations should rely on MDM solutions, which have much more secure authentication requirements, to perform remote lock and remote wipe.
    "
  impact 0
  describe command("/usr/bin/profiles -P -o stdout | /usr/bin/grep -Ec '(allowFindMyDevice = 0|allowFindMyFriends = 0|DisableFMMiCloudSetting = 1)'")     do
    its('exit_status') { should eq 3 }
  end
end
control 'sysprefs_content_caching_disable' do
  title 'Disable Content Caching Service'
  desc     "
    Content caching _MUST_ be disabled. 
    Content caching is a macOS service that helps reduce Internet data usage and speed up software installation on Mac computers. It is not recommended for devices furnished to employees to act as a caching server. 
    "
  impact 0
  describe command("/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'allowContentCaching = 0'")     do
    its('exit_status') { should eq 1 }
  end
end
control 'sysprefs_location_services_disable' do
  title 'Disable Location Services'
  desc     "
    Location Services _MUST_ be disabled. 
    The information system _MUST_ be configured to provide only essential capabilities.  Disabling Location Services helps prevent the unauthorized connection of devices, unauthorized transfer of information, and unauthorized tunneling.
    "
  impact 0.5
  describe command("/usr/bin/defaults read /var/db/locationd/Library/Preferences/ByHost/com.apple.locationd.plist LocationServicesEnabled")     do
    its('exit_status') { should eq 0 }
  end
end
control 'sysprefs_time_server_configure' do
  title 'Configure macOS to Use an Authorized Time Server'
  desc     "
    Approved time servers _MUST_ be the only servers configured for use.
    This rule ensures the uniformity of time stamps for information systems with multiple system clocks and systems connected over a network.
    "
  impact 0.5
  describe command("/usr/bin/profiles -P -o stdout | /usr/bin/awk -F \"= \" '/timeServer/{print $2}' | /usr/bin/tr -d ';' | /usr/bin/tr -d '\"'")     do
    its('stdout') { should match(/time-a.nist.gov,time-b.nist.gov/) }
  end
end
control 'sysprefs_power_nap_disable' do
  title 'Disable Power Nap'
  desc     "
    Power Nap _MUST_ be disabled.
    Power Nap allows your Mac to perform actions while a Mac is asleep. This can interfere with USB power and may cause devices to stop functioning until a reboot and must therefore be disabled on all applicable systems. 
    The following Macs support Power Nap:
    * MacBook (Early 2015 and later)
    * MacBook Air (Late 2010 and later)
    * MacBook Pro (all models with Retina display)
    * Mac mini (Late 2012 and later)
    * iMac (Late 2012 and later)
    * Mac Pro (Late 2013 and later)
    "
  impact 0
  describe command("/usr/bin/pmset -g custom | /usr/bin/awk '/powernap/ { sum+=$2 } END {print sum}'")     do
    its('exit_status') { should eq 0 }
  end
end
control 'sysprefs_diagnostics_reports_disable' do
  title 'Disable Sending Diagnostic and Usage Data to Apple'
  desc     "
    The ability to submit diagnostic data to Apple _MUST_ be disabled.
    The information system _MUST_ be configured to provide only essential capabilities. Disabling the submission of diagnostic and usage information will mitigate the risk of unwanted data being sent to Apple. 
    "
  impact 0.5
  describe command("/usr/bin/profiles -P -o stdout | /usr/bin/grep -Ec '(allowDiagnosticSubmission = 0|AutoSubmit = 0)'")     do
    its('exit_status') { should eq 2 }
  end
end
control 'sysprefs_bluetooth_disable' do
  title 'Disable Bluetooth When no Approved Device is Connected'
  desc     "
    The macOS system _MUST_ be configured to disable Bluetooth unless there is an approved device connected.
    [IMPORTANT]
    ====
    Information System Security Officers (ISSOs) may make the risk-based decision not to disable Bluetooth, so as to maintain necessary functionality, but they are advised to first fully weigh the potential risks posed to their organization. 
    ====
    "
  impact 0.1
  describe command("/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'DisableBluetooth = 1'")     do
    its('exit_status') { should eq 1 }
  end
end
control 'sysprefs_loginwindow_prompt_username_password_enforce' do
  title 'Configure Login Window to Prompt for Username and Password'
  desc     "
    The login window _MUST_ be configured to prompt all users for both a username and a password. 
    By default, the system displays a list of known users on the login window, which can make it easier for a malicious user to gain access to someone else’s account. Requiring users to type in both their username and password mitigates the risk of unauthorized users gaining access to the information system. 
    "
  impact 0
  describe command("/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'SHOWFULLNAME = 1'")     do
    its('exit_status') { should eq 1 }
  end
end
control 'sysprefs_automatic_login_disable' do
  title 'Disable Unattended or Automatic Logon to the System'
  desc     "
    Automatic logon _MUST_ be disabled.
    When automatic logons are enabled, the default user account is automatically logged on at boot time without prompting the user for a password. Even if the screen is later locked, a malicious user would be able to reboot the computer and find it already logged in. Disabling automatic logons mitigates this risk.
    "
  impact 0.5
  describe command("/usr/bin/profiles -P -o stdout | /usr/bin/grep -c '\"com.apple.login.mcx.DisableAutoLoginClient\" = 1'")     do
    its('exit_status') { should eq 1 }
  end
end
control 'sysprefs_apple_watch_unlock_disable' do
  title 'Prevent Apple Watch from Terminating a Session Lock'
  desc     "
    Apple Watches are not an approved authenticator and their use _MUST_ be disabled.
    Disabling Apple watches is a necessary step to ensuring that the information system retains a session lock until the user reestablishes access using an authorized identification and authentication procedures.
    "
  impact 0.5
  describe command("/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'allowAutoUnlock = 0'")     do
    its('exit_status') { should eq 1 }
  end
end
control 'sysprefs_token_removal_enforce' do
  title 'Configure User Session Lock When a Smart Token is Removed'
  desc     "
    The screen lock _MUST_ be configured to initiate automatically when the smart token is removed from the system.
    Session locks are temporary actions taken when users stop work and move away from the immediate vicinity of the information system but do not want to log out because of the temporary nature of their absences. While a session lock is not an acceptable substitute for logging out of an information system for longer periods of time, they prevent a malicious user from accessing the information system when a user has removed their smart token. 
    [IMPORTANT]
    ====
    Information System Security Officers (ISSOs) may make the risk-based decision not to enforce a session lock when a smart token is removed, so as to maintain necessary workflow capabilities, but they are advised to first fully weigh the potential risks posed to their organization. 
    ====
    "
  impact 0.5
  describe command("/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'tokenRemovalAction = 1'")     do
    its('exit_status') { should eq 1 }
  end
end
control 'sysprefs_screensaver_ask_for_password_delay_enforce' do
  title 'Enforce Session Lock After Screen Saver is Started'
  desc     "
    A screen saver _MUST_ be enabled and the system _MUST_ be configured to require a password to unlock once the screensaver has been on for a maximum of five seconds. 
    An unattended system with an excessive grace period is vulnerable to a malicious user. 
    "
  impact 0.5
  describe command("/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'askForPasswordDelay = 5'")     do
    its('exit_status') { should eq 1 }
  end
end
control 'sysprefs_wifi_disable' do
  title 'Disable Wi-Fi Interface'
  desc     "
    The macOS system must be configured with Wi-Fi support software disabled. 
    Allowing devices and users to connect to or from the system without first authenticating them allows untrusted access and can lead to a compromise or attack. Since wireless communications can be intercepted  it is necessary to use encryption to protect the confidentiality of information in transit.Wireless technologies include  for example  microwave  packet radio (UHF/VHF)  802.11x  and Bluetooth. Wireless networks use authentication protocols (e.g.  EAP/TLS  PEAP)  which provide credential protection and mutual authentication.
    NOTE: If the system requires Wi-Fi to connect to an authorized network, this is not applicable.
    "
  impact 0.5
  describe command("/usr/sbin/networksetup -listallnetworkservices | /usr/bin/grep -c \"*Wi-Fi\"")     do
    its('exit_status') { should eq 1 }
  end
end
control 'sysprefs_time_server_enforce' do
  title 'Enable macOS Time Synchronization Daemon (timed)'
  desc     "
    The timed service _MUST_ be enabled on all networked systems and configured to set time automatically from the approved time server.
    This rule ensures the uniformity of time stamps for information systems with multiple system clocks and systems connected over a network.
    "
  impact 0.5
  describe command("/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'TMAutomaticTimeOnlyEnabled = 1'")     do
    its('exit_status') { should eq 1 }
  end
end
control 'sysprefs_touchid_unlock_disable' do
  title 'Disable TouchID for Unlocking the Device'
  desc     "
    TouchID enables the ability to unlock a Mac system with a user’s fingerprint. 
    TouchID _MUST_ be disabled for \"Unlocking your Mac\" on all macOS devices that are capable of using Touch ID. 
    The system _MUST_ remain locked until the user establishes access using an authorized identification and authentication method. 
    "
  impact 0
  describe command("/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'allowFingerprintForUnlock = 0'")     do
    its('exit_status') { should eq 1 }
  end
end
control 'sysprefs_screen_sharing_disable' do
  title 'Disable Screen Sharing and Apple Remote Desktop'
  desc     "
    Support for both Screen Sharing and Apple Remote Desktop (ARD) is non-essential and _MUST_ be disabled.
    The information system _MUST_ be configured to provide only essential capabilities. Disabling screen sharing and ARD helps prevent the unauthorized connection of devices, the unauthorized transfer of information, and unauthorized tunneling.
    "
  impact 0.5
  describe command("/bin/launchctl print-disabled system | /usr/bin/grep -c '\"com.apple.screensharing\" => true'")     do
    its('exit_status') { should eq 1 }
  end
end
control 'sysprefs_hot_corners_disable' do
  title 'Disable Hot Corners'
  desc     "
    Hot corners _MUST_ be disabled. 
    The information system conceals, via the session lock, information previously visible on the display with a publicly viewable image. Although hot comers can be used to initiate a session lock or to launch useful applications, they can also be configured to disable an automatic session lock from initiating. Such a configuration introduces the risk that a user might forget to manually lock the screen before stepping away from the computer.
    "
  impact 0.5
  describe command("/usr/bin/profiles -P -o stdout | /usr/bin/grep -Ec '\"wvous-bl-corner\" = 0|\"wvous-br-corner\" = 0|\"wvous-tl-corner\" = 0|\"wvous-tr-corner\" = 0'")     do
    its('exit_status') { should eq 4 }
  end
end
control 'sysprefs_siri_disable' do
  title 'Disable Siri'
  desc     "
    Support for Siri is non-essential and _MUST_ be disabled.
    The information system _MUST_ be configured to provide only essential capabilities.
    "
  impact 0.5
  describe command("/usr/bin/profiles -P -o stdout | /usr/bin/grep -c '\"Ironwood Allowed\" = 0'")     do
    its('exit_status') { should eq 1 }
  end
end
control 'sysprefs_filevault_enforce' do
  title 'Enforce FileVault'
  desc     "
    FileVault _MUST_ be enforced.
    The information system implements cryptographic mechanisms to protect the confidentiality and integrity of information stored on digital media during transport outside of controlled areas.
    "
  impact 0.5
  describe command("/usr/bin/fdesetup status | /usr/bin/grep -c \"FileVault is On.\"")     do
    its('exit_status') { should eq 1 }
  end
end
control 'sysprefs_password_hints_disable' do
  title 'Disable Password Hints'
  desc     "
    Password hints _MUST_ be disabled.
    Password hints leak information about passwords that are currently in use and can lead to loss of confidentiality. 
    "
  impact 0.5
  describe command("/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'RetriesUntilHint = 0'")     do
    its('exit_status') { should eq 1 }
  end
end
control 'sysprefs_bluetooth_sharing_disable' do
  title 'Disable Bluetooth Sharing'
  desc     "
    Bluetooth Sharing _MUST_ be disabled. 
    Bluetooth Sharing allows users to wirelessly transmit files between the macOS and Bluetooth-enabled devices, including personally owned cellphones and tablets. A malicious user might introduce viruses or malware onto the system or extract sensitive files via Bluetooth Sharing. When Bluetooth Sharing is disabled, this risk is mitigated. 
    [NOTE] 
    ====
    The check and fix are for the currently logged in user. To get the currently logged in user, run the following.
    [source,bash]
    ----
    CURRENT_USER=$( scutil <<< \"show State:/Users/ConsoleUser\" \| awk '/Name :/ && ! /loginwindow/ { print $3 }' )
    ----
    ====
    "
  impact 0
  describe command("/usr/bin/sudo -u \"$CURRENT_USER\" /usr/bin/defaults -currentHost read com.apple.Bluetooth PrefKeyServicesEnabled")     do
    its('exit_status') { should eq 0 }
  end
end
control 'sysprefs_improve_siri_dictation_disable' do
  title 'Disable Sending Siri and Dictation Information to Apple'
  desc     "
    The ability for Apple to store and review audio of your Siri and Dictation interactions _MUST_ be disabled.
    The information system _MUST_ be configured to provide only essential capabilities. Disabling the submission of Siri and Dictation information will mitigate the risk of unwanted data being sent to Apple. 
    "
  impact 0
  describe command("/usr/bin/profiles -P -o stdout | /usr/bin/grep -c '\"Siri Data Sharing Opt-In Status\" = 2;'")     do
    its('exit_status') { should eq 1 }
  end
end
