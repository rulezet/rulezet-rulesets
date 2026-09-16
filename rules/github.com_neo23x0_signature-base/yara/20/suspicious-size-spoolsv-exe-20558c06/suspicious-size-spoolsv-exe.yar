rule Suspicious_Size_spoolsv_exe {
   meta:
      description = "Detects uncommon file size of spoolsv.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      score = 60
      date = "2015-12-23"
      modified = "2025-03-17"
      noarchivescan = 1
      id = "14bb3463-b99f-57e1-8cff-fe9a34771093"
   condition:
      uint16(0) == 0x5a4d
      and filename == "spoolsv.exe"
      and (filesize < 50KB or filesize > 1500KB)
}