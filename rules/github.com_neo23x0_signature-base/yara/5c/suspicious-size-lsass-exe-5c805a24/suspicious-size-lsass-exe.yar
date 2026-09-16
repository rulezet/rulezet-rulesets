rule Suspicious_Size_lsass_exe {
   meta:
      description = "Detects uncommon file size of lsass.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      score = 60
      date = "2015-12-21"
      noarchivescan = 1
      id = "005661c7-7576-5c13-9534-b49c12b2faad"
   condition:
      uint16(0) == 0x5a4d
      and filename == "lsass.exe"
      and (filesize < 10KB or filesize > 100KB)
}