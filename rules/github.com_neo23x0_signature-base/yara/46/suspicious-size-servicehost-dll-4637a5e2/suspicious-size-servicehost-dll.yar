rule Suspicious_Size_servicehost_dll {
   meta:
      description = "Detects uncommon file size of servicehost.dll"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      score = 60
      date = "2015-12-23"
      noarchivescan = 1
      id = "ac71393c-a475-59e0-b22a-d5ee3d25084b"
   condition:
      uint16(0) == 0x5a4d
      and filename == "servicehost.dll"
      and filesize > 150KB
}