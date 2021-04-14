control 'auth_pam_login_smartcard_enforce' do
  title 'Enforce Multifactor Authentication for Login'
  desc     "
    The system _MUST_ be configured to enforce multifactor authentication.
    All users _MUST_ go through multifactor authentication to prevent unauthenticated access and potential compromise to the system.
    NOTE: /etc/pam.d/login will be automatically modified to its original state following any update or major upgrade to the operating system.
    "
  impact 0.5
  describe command("/usr/bin/grep -Ec '^(auths+sufficients+pam_smartcard.so|auths+requireds+pam_deny.so)' /etc/pam.d/login")     do
    its('exit_status') { should eq 2 }
  end
end
control 'auth_smartcard_allow' do
  title 'Allow Smartcard Authentication'
  desc     "
    Smartcard authentication _MUST_ be allowed. 
    The use of smartcard credentials facilitates standardization and reduces the risk of unauthorized access.
    When enabled, the smartcard can be used for login, authorization, and screen saver unlocking.
    "
  impact 0
  describe command("/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'allowSmartCard = 1'")     do
    its('exit_status') { should eq 1 }
  end
end
control 'auth_pam_sudo_smartcard_enforce' do
  title 'Enforce Multifactor Authentication for Privilege Escalation Through the sudo Command'
  desc     "
    The system _MUST_ be configured to enforce multifactor authentication when the sudo command is used to elevate privilege. 
    All users _MUST_ go through multifactor authentication to prevent unauthenticated access and potential compromise to the system.
    NOTE: /etc/pam.d/sudo will be automatically modified to its original state following any update or major upgrade to the operating system.
    "
  impact 0.5
  describe command("/usr/bin/grep -Ec '^(auths+sufficients+pam_smartcard.so|auths+requireds+pam_deny.so)' /etc/pam.d/sudo")     do
    its('exit_status') { should eq 2 }
  end
end
control 'auth_ssh_smartcard_enforce' do
  title 'Enforce Smartcard Authentication for SSH'
  desc     "
    If remote login through SSH is enabled, smartcard authentication _MUST_ be enforced for user login.
    All users _MUST_ go through multifactor authentication to prevent unauthenticated access and potential compromise to the system.
    NOTE: /etc/ssh/sshd_config will be automatically modified to its original state following any update or major upgrade to the operating system.
    "
  impact 0
  describe command("/usr/bin/grep -Ec '^(PasswordAuthentications+no|ChallengeResponseAuthentications+no)' /etc/ssh/sshd_config")     do
    its('exit_status') { should eq 2 }
  end
end
control 'auth_smartcard_certificate_trust_enforce_high' do
  title 'Set Smartcard Certificate Trust to High'
  desc     "
    The macOS system _MUST_ be configured to block access to users who are no longer authorized (i.e., users with revoked certificates).  
    To prevent the use of untrusted certificates, the certificates on a smartcard card _MUST_ meet the following criteria: its issuer has a system-trusted certificate, the certificate is not expired, its \"valid-after\" date is in the past, and it passes Certificate Revocation List (CRL) and Online Certificate Status Protocol (OCSP) checking.
    By setting the smartcard certificate trust level to high, the system will execute a hard revocation, i.e., a network connection is required. A verified positive response from the OSCP/CRL server is required for authentication to succeed.
    NOTE: Before applying this setting, please see the smartcard supplemental guidance.
    "
  impact 0
  describe command("/usr/bin/profiles -P -o stdout | /usr/bin/awk '/checkCertificateTrust/{print substr($3, 1, length($3)-1)}'")     do
    its('exit_status') { should eq 3 }
  end
end
control 'auth_smartcard_certificate_trust_enforce_moderate' do
  title 'Set Smartcard Certificate Trust to Moderate'
  desc     "
    The macOS system _MUST_ be configured to block access to users who are no longer authorized (i.e., users with revoked certificates).  
    To prevent the use of untrusted certificates, the certificates on a smartcard card _MUST_ meet the following criteria: its issuer has a system-trusted certificate, the certificate is not expired, its \"valid-after\" date is in the past, and it passes Certificate Revocation List (CRL) and Online Certificate Status Protocol (OCSP) checking.
    By setting the smartcard certificate trust level to moderate, the system will execute a soft revocation, i.e., if the OCSP/CRL server is unreachable, authentication will still succeed.
    NOTE: Before applying this setting, please see the smartcard supplemental guidance.
    "
  impact 0.5
  describe command("/usr/bin/profiles -P -o stdout | /usr/bin/awk '/checkCertificateTrust/{print substr($3, 1, length($3)-1)}'")     do
    its('exit_status') { should eq 2 }
  end
end
control 'auth_smartcard_enforce' do
  title 'Enforce Smartcard Authentication'
  desc     "
    Smartcard authentication _MUST_ be enforced.
    The use of smartcard credentials facilitates standardization and reduces the risk of unauthorized access.
    When enforceSmartCard is set to “true”, the smartcard must be used for login, authorization, and unlocking the screensaver.
    CAUTION: enforceSmartCard will apply to the whole system. No users will be able to login with their password unless the profile is removed or a member of the NotEnforced group.
    NOTE: enforceSmartcard requires allowSmartcard to be set to true in order to work.
    "
  impact 1.0
  describe command("/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'enforceSmartCard = 1'")     do
    its('exit_status') { should eq 1 }
  end
end
control 'auth_pam_su_smartcard_enforce' do
  title 'Enforce Multifactor Authentication for the su Command'
  desc     "
    The system _MUST_ be configured such that, when the su command is used, multifactor authentication is enforced.
    All users _MUST_ go through multifactor authentication to prevent unauthenticated access and potential compromise to the system.
    NOTE: /etc/pam.d/su will be automatically modified to its original state following any update or major upgrade to the operating system.
    "
  impact 0.5
  describe command("/usr/bin/grep -Ec '^(auths+sufficients+pam_smartcard.so|auths+requireds+pam_rootok.so)' /etc/pam.d/su")     do
    its('exit_status') { should eq 2 }
  end
end
