rule Suspicious_Size_firefox_exe {
   meta:
      description = "Detects uncommon file size of firefox.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      score = 60
      date = "2015-12-21"
      modified = "2024-06-03"
      noarchivescan = 1
      id = "73c4b838-9277-5756-a35d-4a644be5ad5d"
   condition:
      uint16(0) == 0x5a4d
      and filename == "firefox.exe"
      and (filesize < 265KB or filesize > 910KB)
      and not filepath contains "Malwarebytes"
}