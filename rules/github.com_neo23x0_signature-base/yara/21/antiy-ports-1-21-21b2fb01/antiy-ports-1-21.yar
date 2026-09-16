rule Antiy_Ports_1_21 {
   meta:
      description = "Disclosed hacktool set (old stuff) - file Antiy Ports 1.21.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "23.11.14"
      score = 60
      hash = "ebf4bcc7b6b1c42df6048d198cbe7e11cb4ae3f0"
      id = "eb53fc91-4dec-5416-a2c7-1e8256297886"
   strings:
      $s0 = "AntiyPorts.EXE" fullword wide
      $s7 = "AntiyPorts MFC Application" fullword wide
      $s20 = " @Stego:" fullword ascii
   condition:
      all of them
}