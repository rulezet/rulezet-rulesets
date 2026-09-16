rule Suspicious_Size_svchost_exe {
   meta:
      description = "Detects uncommon file size of svchost.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      score = 60
      date = "2015-12-21"
      noarchivescan = 1
      id = "31a8d00e-ebfc-5001-9c58-d3a2580f16b3"
   condition:
      uint16(0) == 0x5a4d
      and filename == "svchost.exe"
      and (filesize < 14KB or filesize > 100KB)
}