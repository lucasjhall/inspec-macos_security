control 'pwpolicy_account_inactivity_enforce' do
  title 'Disable Accounts after 35 Days of Inactivity'
  desc     "
    The macOS _MUST_ be configured to disable accounts after 35 days of inactivity.
    This rule prevents malicious users from making use of unused accounts to gain access to the system while avoiding detection. 
    "
  impact 0
  describe command("/usr/bin/pwpolicy getaccountpolicies | /usr/bin/grep -v \"Getting global account policies\" | /usr/bin/xmllint --xpath '/plist/dict/array/dict/dict[key=\"policyAttributeInactiveDays\"]/integer' - | /usr/bin/awk -F '[<>]' '{print $3}'")     do
    its('exit_status') { should eq 35 }
  end
end
control 'pwpolicy_history_enforce' do
  title 'Prohibit Password Reuse for a Minimum of Five Generations'
  desc     "
    The macOS _MUST_ be configured to enforce a password history of at least five previous passwords when a password is created. 
    This rule ensures that users are  not allowed to re-use a password that was used in any of the five previous password generations. 
    Limiting password reuse protects against malicious users attempting to gain access to the system via brute-force hacking methods.
    "
  impact 0.5
  describe command("/usr/bin/profiles -P -o stdout | /usr/bin/awk '/pinHistory/{sub(/;.*/,\"\");print $3}'")     do
    its('exit_status') { should eq 5 }
  end
end
control 'pwpolicy_account_lockout_enforce' do
  title 'Limit Consecutive Failed Login Attempts to Three'
  desc     "
    The macOS _MUST_ be configured to limit the number of failed login attempts to a maximum of three. When the maximum number of failed attempts is reached, the account _MUST_ be locked for a period of time after.
    This rule protects against malicious users attempting to gain access to the system via brute-force hacking methods. 
    "
  impact 0.5
  describe command("/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'maxFailedAttempts = 3'")     do
    its('exit_status') { should eq 1 }
  end
end
control 'pwpolicy_simple_sequence_disable' do
  title 'Prohibit Repeating, Ascending, and Descending Character Sequences'
  desc     "
    The macOS _MUST_ be configured to prohibit the use of repeating, ascending, and descending character sequences when a password is created.
    This rule enforces password complexity by requiring users to set passwords that are less vulnerable to malicious users.
    "
  impact 0
  describe command("/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'allowSimple = 0'")     do
    its('exit_status') { should eq 1 }
  end
end
control 'pwpolicy_lower_case_character_enforce' do
  title 'Require Passwords Contain a Minimum of One Lowercase Character'
  desc     "
    The macOS _MUST_ be configured to require at least one lower-case character be used when a password is created.
    This rule enforces password complexity by requiring users to set passwords that are less vulnerable to malicious users. 
    "
  impact 0
  describe command("/usr/bin/pwpolicy getaccountpolicies | /usr/bin/grep -v \"Getting global account policies\" | /usr/bin/xmllint --xpath '/plist/dict/array/dict/dict[key=\"minimumAlphaCharactersLowerCase\"]/integer' - | /usr/bin/awk -F '[<>]' '{print $3}'")     do
    its('exit_status') { should eq 1 }
  end
end
control 'pwpolicy_account_lockout_timeout_enforce' do
  title 'Set Account Lockout Time to 15 Minutes'
  desc     "
    The macOS _MUST_ be configured to enforce a lockout time period of at least 15 minutes when the maximum number of failed logon attempts is reached.
    This rule protects against malicious users attempting to gain access to the system via brute-force hacking methods. 
    "
  impact 0.5
  describe command("/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'minutesUntilFailedLoginReset = 15'")     do
    its('exit_status') { should eq 1 }
  end
end
control 'pwpolicy_special_character_enforce' do
  title 'Require Passwords Contain a Minimum of One Special Character'
  desc     "
    The macOS _MUST_ be configured to require at least one special character be used when a password is created.
    Special characters are those characters that are not alphanumeric. Examples include: ~ ! @ # $ % ^ *.
    This rule enforces password complexity by requiring users to set passwords that are less vulnerable to malicious users.
    "
  impact 0.5
  describe command("/usr/bin/profiles -P -o stdout | /usr/bin/awk '/minComplexChars/{sub(/;.*/,\"\");print $3}'")     do
    its('exit_status') { should eq 1 }
  end
end
control 'pwpolicy_alpha_numeric_enforce' do
  title 'Require Passwords Contain a Minimum of One Numeric Character'
  desc     "
    The macOS _MUST_ be configured to require at least one numeric character be used when a password is created.
    This rule enforces password complexity by requiring users to set passwords that are less vulnerable to malicious users. 
    "
  impact 0.5
  describe command("/usr/bin/profiles -P -o stdout | /usr/bin/grep -c \"requireAlphanumeric = 1;\"")     do
    its('exit_status') { should eq 1 }
  end
end
control 'pwpolicy_minimum_length_enforce' do
  title 'Require a Minimum Password Length of 15 Characters'
  desc     "
    The macOS _MUST_ be configured to require a minimum of 15 characters be used when a password is created.
    This rule enforces password complexity by requiring users to set passwords that are less vulnerable to malicious users. 
    "
  impact 0.5
  describe command("/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'minLength = 15'")     do
    its('exit_status') { should eq 1 }
  end
end
control 'pwpolicy_upper_case_character_enforce' do
  title 'Require Passwords Contain a Minimum of One Uppercase Character'
  desc     "
    The macOS _MUST_ be configured to require at least one uppercase character be used when a password is created.
    This rule enforces password complexity by requiring users to set passwords that are less vulnerable to malicious users. 
    "
  impact 0
  describe command("/usr/bin/pwpolicy getaccountpolicies | /usr/bin/grep -v \"Getting global account policies\" | /usr/bin/xmllint --xpath '/plist/dict/array/dict/dict[key=\"minimumAlphaCharactersUpperCase\"]/integer' - | /usr/bin/awk -F '[<>]' '{print $3}'")     do
    its('exit_status') { should eq 1 }
  end
end
control 'pwpolicy_60_day_enforce' do
  title 'Restrict Maximum Password Lifetime to 60 Days'
  desc     "
    The macOS _MUST_ be configured to enforce a maximum password lifetime limit of at least 60 days. 
    This rule ensures that users are forced to change their passwords frequently enough to prevent malicious users from gaining and maintaining access to the system.
    "
  impact 0.5
  describe command("/usr/bin/profiles -P -o stdout | /usr/bin/awk -F \" = \" '/maxPINAgeInDays/{sub(/;.*/,\"\");print $2}'")     do
    its('exit_status') { should eq 60 }
  end
end
control 'pwpolicy_minimum_lifetime_enforce' do
  title 'Set Minimum Password Lifetime to 24 Hours'
  desc     "
    The macOS _MUST_ be configured to enforce a minimum password lifetime limit of 24 hours.
    This rule discourages users from cycling through their previous passwords to get back to a preferred one.
    "
  impact 0
  describe command("/usr/bin/pwpolicy getaccountpolicies | /usr/bin/grep -v \"Getting global account policies\" | /usr/bin/xmllint --xpath '/plist/dict/array/dict/dict[key=\"policyAttributeMinimumLifetimeHours\"]/integer' - | /usr/bin/awk -F '[<>]' '{print $3}'")     do
    its('exit_status') { should eq 24 }
  end
end
