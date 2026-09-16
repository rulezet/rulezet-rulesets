rule Suspicious_Size_csrss_exe {
   meta:
      description = "Detects uncommon file size of csrss.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      score = 60
      date = "2015-12-21"
      modified = "2022-01-28"
      noarchivescan = 1
      id = "5a247b51-6c91-5753-95b3-4a4c2b2286eb"
   condition:
      uint16(0) == 0x5a4d
      and filename == "csrss.exe"
      and (filesize > 50KB)
}