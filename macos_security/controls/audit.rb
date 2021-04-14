control 'audit_flags_fd_configure' do
  title 'Configure System to Audit All Deletions of Object Attributes'
  desc     "
    The audit system _MUST_ be configured to record enforcement actions of attempts to delete file attributes (fd). 
    ***Enforcement actions are the methods or mechanisms used to prevent unauthorized changes to configuration settings. One common and effective enforcement action method is using access restrictions (i.e., denying modifications to a file by applying file permissions). 
    This configuration ensures that audit lists include events in which enforcement actions prevent attempts to delete a file. 
    Without auditing the enforcement of access restrictions, it is difficult to identify attempted attacks, as there is no audit trail available for forensic investigation.
    "
  impact 0.5
  describe command("/usr/bin/grep -Ec \"^flags.*-fd\" /etc/security/audit_control")     do
    its('exit_status') { should eq 1 }
  end
end
control 'audit_folder_group_configure' do
  title 'Configure Audit Log Folders Group to Wheel'
  desc     "
    Audit log files _MUST_ have the group set to wheel.
    The audit service _MUST_ be configured to create log files with the correct group ownership to prevent normal users from reading audit logs. 
    Audit logs contain sensitive data about the system and users. If log files are set to be readable and writable only by system administrators, the risk is mitigated.
    "
  impact 0.5
  describe command("/bin/ls -dn $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/awk '{print $4}'")     do
    its('exit_status') { should eq 0 }
  end
end
control 'audit_failure_halt' do
  title 'Configure System to Shut Down Upon Audit Failure'
  desc     "
    The audit service _MUST_ be configured to shut down the computer if it is unable to audit system events. 
    Once audit failure occurs, user and system activity are no longer recorded, and malicious activity could go undetected. Audit processing failures can occur due to software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded. 
    "
  impact 0.5
  describe command("/usr/bin/grep -Ec \"^policy.*ahlt\" /etc/security/audit_control")     do
    its('exit_status') { should eq 1 }
  end
end
control 'audit_acls_folders_configure' do
  title 'Configure Audit Log Folder to Not Contain Access Control Lists'
  desc     "
    The audit log folder _MUST_ not contain access control lists (ACLs).
    Audit logs contain sensitive data about the system and users. This rule ensures that the audit service is configured to create log folders that are readable and writable only by system administrators in order to prevent normal users from reading audit logs.
    "
  impact 0.5
  describe command("/bin/ls -lde $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/awk '{print $1}' | /usr/bin/grep -c \":\"")     do
    its('exit_status') { should eq 0 }
  end
end
control 'audit_flags_fm_configure' do
  title 'Configure System to Audit All Change of Object Attributes'
  desc     "
    The audit system _MUST_ be configured to record enforcement actions of attempts to modify file attributes (fm). 
    Enforcement actions are the methods or mechanisms used to prevent unauthorized changes to configuration settings. One common and effective enforcement action method is using access restrictions (i.e., denying modifications to a file by applying file permissions). 
    This configuration ensures that audit lists include events in which enforcement actions prevent attempts to modify a file. 
    Without auditing the enforcement of access restrictions, it is difficult to identify attempted attacks, as there is no audit trail available for forensic investigation.
    "
  impact 0.5
  describe command("/usr/bin/grep -Ec \"^flags.*fm\" /etc/security/audit_control")     do
    its('exit_status') { should eq 1 }
  end
end
control 'audit_auditd_enabled' do
  title 'Enable Security Auditing'
  desc     "
    The information system _MUST_ be configured to generate audit records. 
    Audit records establish what types of events have occurred, when they occurred, and which users were involved. These records aid an organization in their efforts to establish, correlate, and investigate the events leading up to an outage or attack.
    The content required to be captured in an audit record varies based on the impact level of an organization’s system. Content that may be necessary to satisfy this requirement includes, for example, time stamps, source addresses, destination addresses, user identifiers, event descriptions, success/fail indications, filenames involved, and access or flow control rules invoked.
    The information system initiates session audits at system start-up.
    "
  impact 0.5
  describe command("/bin/launchctl list | /usr/bin/grep -c com.apple.auditd")     do
    its('exit_status') { should eq 1 }
  end
end
control 'audit_flags_ad_configure' do
  title 'Configure System to Audit All Administrative Action Events'
  desc     "
    The auditing system _MUST_ be configured to flag administrative action (ad) events.
    Administrative action events include changes made to the system (e.g. modifying authentication policies). If audit records do not include ad events, it is difficult to identify incidents and to correlate incidents to subsequent events. 
    Audit records can be generated from various components within the information system (e.g., via a module or policy filter). 
    The information system audits the execution of privileged functions.
    "
  impact 0.5
  describe command("/usr/bin/grep -Ec \"^flags.*ad\" /etc/security/audit_control")     do
    its('exit_status') { should eq 1 }
  end
end
control 'audit_flags_ex_configure' do
  title 'Configure System to Audit All Failed Program Execution on the System'
  desc     "
    The audit system _MUST_ be configured to record enforcement actions of access restrictions, including failed program execute (-ex) attempts.
    Enforcement actions are the methods or mechanisms used to prevent unauthorized access and/or changes to configuration settings. One common and effective enforcement action method is using program execution restrictions (e.g., denying users access to execute certain processes). 
    This configuration ensures that audit lists include events in which program execution has failed. 
    Without auditing the enforcement of program execution, it is difficult to identify attempted attacks, as there is no audit trail available for forensic investigation.
    "
  impact 0
  describe command("/usr/bin/grep -Ec \"^flags.*-ex\" /etc/security/audit_control")     do
    its('exit_status') { should eq 1 }
  end
end
control 'audit_files_mode_configure' do
  title 'Configure Audit Log Files to Mode 440 or Less Permissive'
  desc     "
    The audit service _MUST_ be configured to create log files that are readable only by the root user and group wheel. To achieve this, audit log files _MUST_ be configured to mode 440 or less permissive; thereby preventing normal users from reading, modifying or deleting audit logs. 
    "
  impact 0.5
  describe command("/bin/ls -l $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/awk '!/-r--r-----|current|total/{print $1}' | /usr/bin/wc -l | /usr/bin/tr -d ' '")     do
    its('exit_status') { should eq 0 }
  end
end
control 'audit_flags_aa_configure' do
  title 'Configure System to Audit All Authorization and Authentication Events'
  desc     "
    The auditing system _MUST_ be configured to flag authorization and authentication (aa) events.
    Authentication events contain information about the identity of a user, server, or client. Authorization events contain information about permissions, rights, and rules. If audit records do not include aa events, it is difficult to identify incidents and to correlate incidents to subsequent events. 
    Audit records can be generated from various components within the information system (e.g., via a module or policy filter).
    "
  impact 0.5
  describe command("/usr/bin/grep -Ec \"^flags.*aa\" /etc/security/audit_control")     do
    its('exit_status') { should eq 1 }
  end
end
control 'audit_files_owner_configure' do
  title 'Configure Audit Log Files to be Owned by Root'
  desc     "
    Audit log files _MUST_ be owned by root.
    The audit service _MUST_ be configured to create log files with the correct ownership to prevent normal users from reading audit logs.
    Audit logs contain sensitive data about the system and users. If log files are set to only be readable and writable by system administrators, the risk is mitigated.
    "
  impact 0.5
  describe command("/bin/ls -n $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/awk '{s+=$3} END {print s}'")     do
    its('exit_status') { should eq 0 }
  end
end
control 'audit_retention_configure' do
  title 'Configure Audit Retention to a Minimum of Seven Days'
  desc     "
    The audit service _MUST_ be configured to require records be kept for seven days or longer before deletion, unless the system uses a central audit record storage facility. 
    When \"expire-after\" is set to \"7d\", the audit service will not delete audit logs until the log data is at least seven days old.
    "
  impact 0.5
  describe command("/usr/bin/awk -F: '/expire-after/{print $2}' /etc/security/audit_control")     do
    its('stdout') { should match(/7d/) }
  end
end
control 'audit_flags_fr_configure' do
  title 'Configure System to Audit All Failed Read Actions on the System'
  desc     "
    The audit system _MUST_ be configured to record enforcement actions of access restrictions, including failed file read (-fr) attempts. 
    Enforcement actions are the methods or mechanisms used to prevent unauthorized access and/or changes to configuration settings. One common and effective enforcement action method is using access restrictions (e.g., denying access to a file by applying file permissions). 
    This configuration ensures that audit lists include events in which enforcement actions prevent attempts to read a file. 
    Without auditing the enforcement of access restrictions, it is difficult to identify attempted attacks, as there is no audit trail available for forensic investigation.
    "
  impact 0.5
  describe command("/usr/bin/grep -Ec \"^flags.*-fr\" /etc/security/audit_control")     do
    its('exit_status') { should eq 1 }
  end
end
control 'audit_settings_failure_notify' do
  title 'Configure Audit Failure Notification'
  desc     "
    The audit service _MUST_ be configured to immediately print messages to the console or email administrator users when an auditing failure occurs. 
    It is critical for the appropriate personnel to be made aware immediately if a system is at risk of failing to process audit logs as required. Without a real-time alert, security personnel may be unaware of a potentially harmful failure in the auditing system’s capability, and system operation may be adversely affected. 
    "
  impact 0.5
  describe command("/usr/bin/grep -c \"logger -s -p\" /etc/security/audit_warn")     do
    its('exit_status') { should eq 1 }
  end
end
control 'audit_folder_owner_configure' do
  title 'Configure Audit Log Folders to be Owned by Root'
  desc     "
    Audit log files _MUST_ be owned by root.
    The audit service _MUST_ be configured to create log files with the correct ownership to prevent normal users from reading audit logs.
    Audit logs contain sensitive data about the system and users. If log files are set to only be readable and writable by system administrators, the risk is mitigated.
    "
  impact 0.5
  describe command("/bin/ls -dn $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/awk '{print $3}'")     do
    its('exit_status') { should eq 0 }
  end
end
control 'audit_flags_lo_configure' do
  title 'Configure System to Audit All Log In and Log Out Events'
  desc     "
    The audit system _MUST_ be configured to record all attempts to log in and out of the system (lo). 
    Frequently, an attacker that successfully gains access to a system has only gained access to an account with limited privileges, such as a guest account or a service account. The attacker must attempt to change to another user account with normal or elevated privileges in order to proceed. Auditing both successful and unsuccessful attempts to switch to another user account (by way of monitoring login and logout events) mitigates this risk.
    The information system monitors login and logout events.
    "
  impact 0.5
  describe command("/usr/bin/grep -Ec \"^flags*.lo\" /etc/security/audit_control")     do
    its('exit_status') { should eq 1 }
  end
end
control 'audit_flags_fw_configure' do
  title 'Configure System to Audit All Failed Write Actions on the System'
  desc     "
    The audit system _MUST_ be configured to record enforcement actions of access restrictions, including failed file write (-fw) attempts.
    Enforcement actions are the methods or mechanisms used to prevent unauthorized access and/or changes to configuration settings. One common and effective enforcement action method is using access restrictions (e.g., denying users access to edit a file by applying file permissions). 
    This configuration ensures that audit lists include events in which enforcement actions prevent attempts to change a file. 
    Without auditing the enforcement of access restrictions, it is difficult to identify attempted attacks, as there is no audit trail available for forensic investigation.
    "
  impact 0.5
  describe command("/usr/bin/grep -Ec \"^flags.*-fw\" /etc/security/audit_control")     do
    its('exit_status') { should eq 1 }
  end
end
control 'audit_folders_mode_configure' do
  title 'Configure Audit Log Folders to Mode 700 or Less Permissive'
  desc     "
    The audit log folder _MUST_ be configured to mode 700 or less permissive so that only the root user is able to read, write, and execute changes to folders. 
    Because audit logs contain sensitive data about the system and users, the audit service _MUST_ be configured to mode 700 or less permissive; thereby preventing normal users from reading, modifying or deleting audit logs. 
    "
  impact 0.5
  describe command("/usr/bin/stat -f %A $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}')")     do
    its('exit_status') { should eq 700 }
  end
end
control 'audit_configure_capacity_notify' do
  title 'Configure Audit Capacity Warning'
  desc     "
    The audit service _MUST_ be configured to notify the system administrator when the amount of free disk space remaining reaches an organization defined value. 
    This rule ensures that the system administrator is notified in advance that action is required to free up more disk space for audit logs.
    "
  impact 0.5
  describe command("/usr/bin/grep -c \"^minfree:25\" /etc/security/audit_control")     do
    its('exit_status') { should eq 1 }
  end
end
control 'audit_files_group_configure' do
  title 'Configure Audit Log Files Group to Wheel'
  desc     "
    Audit log files _MUST_ have the group set to wheel.
    The audit service _MUST_ be configured to create log files with the correct group ownership to prevent normal users from reading audit logs. 
    Audit logs contain sensitive data about the system and users. If log files are set to be readable and writable only by system administrators, the risk is mitigated.
    "
  impact 0.5
  describe command("/bin/ls -n $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/awk '{s+=$4} END {print s}'")     do
    its('exit_status') { should eq 0 }
  end
end
control 'audit_acls_files_configure' do
  title 'Configure Audit Log Files to Not Contain Access Control Lists'
  desc     "
    The audit log files _MUST_ not contain access control lists (ACLs).
    This rule ensures that audit information and audit files are configured to be readable and writable only by system administrators, thereby preventing unauthorized access, modification, and deletion of files.
    "
  impact 0.5
  describe command("/bin/ls -le $(/usr/bin/awk -F: '/^dir/{print $2}' /etc/security/audit_control) | /usr/bin/awk '{print $1}' | /usr/bin/grep -c \":\"")     do
    its('exit_status') { should eq 0 }
  end
end
