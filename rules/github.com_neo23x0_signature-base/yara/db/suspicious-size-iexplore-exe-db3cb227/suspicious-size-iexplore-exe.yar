rule Suspicious_Size_iexplore_exe {
   meta:
      description = "Detects uncommon file size of iexplore.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      score = 60
      date = "2015-12-21"
      noarchivescan = 1
      id = "d097a599-0fad-574f-8281-46c910e8e54d"
   condition:
      uint16(0) == 0x5a4d
      and filename == "iexplore.exe"
      and not filepath contains "teamviewer"
      and (filesize < 75KB or filesize > 910KB)
}