rule Suspicious_Size_taskhost_exe {
   meta:
      description = "Detects uncommon file size of taskhost.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      score = 60
      date = "2015-12-23"
      modified = "2024-06-10"
      noarchivescan = 1
      id = "71b6c853-f490-5d5a-b481-909f6f3a8798"
   condition:
      uint16(0) == 0x5a4d
      and filename == "taskhost.exe"
      and not filepath contains "/lib/wine/fakedlls"
      and (filesize < 45KB or filesize > 200KB)
}