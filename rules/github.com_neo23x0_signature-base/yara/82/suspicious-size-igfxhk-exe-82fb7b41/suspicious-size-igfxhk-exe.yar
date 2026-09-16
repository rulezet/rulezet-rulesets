rule Suspicious_Size_igfxhk_exe {
   meta:
      description = "Detects uncommon file size of igfxhk.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      score = 60
      date = "2015-12-21"
      modified = "2022-03-08"
      noarchivescan = 1
      id = "18cc167a-3e65-567f-adcf-d2d311520c1d"
   condition:
      uint16(0) == 0x5a4d
      and filename == "igfxhk.exe"
      and (filesize < 200KB or filesize > 300KB)
}