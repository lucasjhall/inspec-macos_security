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
control 'icloud_reminders_disable' do
  title 'Disable iCloud Reminders'
  desc     "
    The macOS built-in Reminders.app connection to Apple’s iCloud service _MUST_ be disabled. 
    Apple’s iCloud service does not provide an organization with enough control over the storage and access of data and, therefore, automated reminders synchronization _MUST_ be controlled by an organization approved service.
    "
  impact 0.1
  describe command("/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'allowCloudReminders = 0'")     do
    its('exit_status') { should eq 1 }
  end
end
control 'icloud_sync_disable' do
  title 'Disable iCloud Desktop and Document Folder Sync'
  desc     "
    The macOS system’s ability to automatically synchronize a user’s desktop and documents folder to their iCloud Drive _MUST_ be disabled.
    Apple’s iCloud service does not provide an organization with enough control over the storage and access of data and, therefore, automated file synchronization _MUST_ be controlled by an organization approved service. 
    "
  impact 0
  describe command("/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'allowCloudDesktopAndDocuments = 0'")     do
    its('exit_status') { should eq 1 }
  end
end
control 'icloud_appleid_prefpane_disable' do
  title 'Disable the System Preference Pane for Apple ID'
  desc     "
    The system preference pane for Apple ID _MUST_ be disabled.
    Disabling the system preference pane prevents login to Apple ID and iCloud. 
    "
  impact 1.0
  describe command("/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'com.apple.preferences.AppleID'")     do
    its('exit_status') { should eq 1 }
  end
end
control 'icloud_keychain_disable' do
  title 'Disable iCloud Keychain Sync'
  desc     "
    The macOS system’s ability to automatically synchronize a user’s passwords to their iCloud account _MUST_ be disabled. 
    Apple’s iCloud service does not provide an organization with enough control over the storage and access of data and, therefore, password management and synchronization _MUST_ be controlled by an organization approved service. 
    "
  impact 0.5
  describe command("/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'allowCloudKeychainSync = 0'")     do
    its('exit_status') { should eq 1 }
  end
end
control 'icloud_notes_disable' do
  title 'Disable iCloud Notes'
  desc     "
    The macOS built-in Notes.app connection to Apple’s iCloud service _MUST_ be disabled. 
    Apple’s iCloud service does not provide an organization with enough control over the storage and access of data and, therefore, automated Notes synchronization _MUST_ be controlled by an organization approved service.
    "
  impact 0.1
  describe command("/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'allowCloudNotes = 0'")     do
    its('exit_status') { should eq 1 }
  end
end
control 'icloud_drive_disable' do
  title 'Disable iCloud Document Sync'
  desc     "
    The macOS built-in iCloud document synchronization service _MUST_ be disabled to prevent organizational data from being synchronized to personal or non-approved storage. 
    Apple’s iCloud service does not provide an organization with enough control over the storage and access of data and, therefore, automated document synchronization _MUST_ be controlled by an organization approved service. 
    "
  impact 0.5
  describe command("/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'allowCloudDocumentSync = 0'")     do
    its('exit_status') { should eq 1 }
  end
end
control 'icloud_bookmarks_disable' do
  title 'Disable iCloud Bookmarks'
  desc     "
    The macOS built-in Safari.app bookmark synchronization via the iCloud service _MUST_ be disabled.
    Apple’s iCloud service does not provide an organization with enough control over the storage and access of data and, therefore, automated bookmark synchronization _MUST_ be controlled by an organization approved service.
    "
  impact 0.5
  describe command("/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'allowCloudBookmarks = 0'")     do
    its('exit_status') { should eq 1 }
  end
end
control 'icloud_mail_disable' do
  title 'Disable iCloud Mail'
  desc     "
    The macOS built-in Mail.app connection to Apple’s iCloud service _MUST_ be disabled.
    Apple’s iCloud service does not provide an organization with enough control over the storage and access of data and, therefore, automated mail synchronization _MUST_ be controlled by an organization approved service.
    "
  impact 0.1
  describe command("/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'allowCloudMail = 0'")     do
    its('exit_status') { should eq 1 }
  end
end
control 'icloud_calendar_disable' do
  title 'Disable the iCloud Calendar Services'
  desc     "
    The macOS built-in Calendar.app connection to Apple’s iCloud service _MUST_ be disabled. 
    Apple’s iCloud service does not provide an organization with enough control over the storage and access of data and, therefore, automated calendar synchronization _MUST_ be controlled by an organization approved service.
    "
  impact 0.1
  describe command("/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'allowCloudCalendar = 0'")     do
    its('exit_status') { should eq 1 }
  end
end
control 'icloud_addressbook_disable' do
  title 'Disable iCloud Address Book'
  desc     "
    The macOS built-in Contacts.app connection to Apple’s iCloud service _MUST_ be disabled. 
    Apple’s iCloud service does not provide an organization with enough control over the storage and access of data, and, therefore, automated contact synchronization _MUST_ be controlled by an organization approved service.
    "
  impact 0.1
  describe command("/usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'allowCloudAddressBook = 0'")     do
    its('exit_status') { should eq 1 }
  end
end
