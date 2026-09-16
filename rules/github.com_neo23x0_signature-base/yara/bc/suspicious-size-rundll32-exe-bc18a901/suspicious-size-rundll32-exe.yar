rule Suspicious_Size_rundll32_exe {
   meta:
      description = "Detects uncommon file size of rundll32.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      score = 60
      date = "2015-12-23"
      noarchivescan = 1
      id = "5b9feae7-17d8-56e4-870a-ef865f2d09bf"
   condition:
      uint16(0) == 0x5a4d
      and filename == "rundll32.exe"
      and (filesize < 30KB or filesize > 120KB)
}