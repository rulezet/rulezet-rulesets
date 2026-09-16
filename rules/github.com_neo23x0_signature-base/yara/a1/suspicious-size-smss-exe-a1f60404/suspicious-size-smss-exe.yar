rule Suspicious_Size_smss_exe {
   meta:
      description = "Detects uncommon file size of smss.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      score = 60
      date = "2015-12-23"
      noarchivescan = 1
      id = "7bdc8953-9240-5d22-b2a6-fe95fbc101c2"
   condition:
      uint16(0) == 0x5a4d
      and filename == "smss.exe"
      and (filesize < 40KB or filesize > 5000KB)
}