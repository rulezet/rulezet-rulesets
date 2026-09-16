rule Suspicious_Size_java_exe {
   meta:
      description = "Detects uncommon file size of java.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      score = 60
      date = "2015-12-21"
      noarchivescan = 1
      id = "b6dc297b-8388-5e39-ba77-c027cdea7afa"
   condition:
      uint16(0) == 0x5a4d
      and filename == "java.exe"
      and (filesize < 30KB or filesize > 900KB)
}