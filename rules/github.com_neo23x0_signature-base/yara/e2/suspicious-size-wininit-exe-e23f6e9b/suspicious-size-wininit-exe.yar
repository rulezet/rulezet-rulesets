rule Suspicious_Size_wininit_exe {
   meta:
      description = "Detects uncommon file size of wininit.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      score = 60
      date = "2015-12-23"
      noarchivescan = 1
      id = "7b58f497-f214-5bf3-8a5c-8edb52749d09"
      modified = "2025-08-13"
   condition:
      uint16(0) == 0x5a4d
      and filename == "wininit.exe"
      and (filesize < 50KB or filesize > 1MB)
}