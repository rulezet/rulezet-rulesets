rule Suspicious_Size_winlogon_exe {
   meta:
      description = "Detects uncommon file size of winlogon.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      score = 60
      date = "2015-12-21"
      noarchivescan = 1
      id = "8665e8d0-3b5f-5227-8879-cdd614123439"
   condition:
      uint16(0) == 0x5a4d
      and filename == "winlogon.exe"
      and (filesize < 279KB or filesize > 970KB)
}