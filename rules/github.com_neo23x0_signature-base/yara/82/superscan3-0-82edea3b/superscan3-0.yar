rule superscan3_0 {
   meta:
      description = "Disclosed hacktool set (old stuff) - file superscan3.0.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "23.11.14"
      score = 60
      hash = "a9a02a14ea4e78af30b8b4a7e1c6ed500a36bc4d"
      id = "d22aa3ae-4c62-5007-896d-7c473f0421a6"
   strings:
      $s0 = "\\scanner.ini" ascii
      $s1 = "\\scanner.exe" ascii
      $s2 = "\\scanner.lst" ascii
      $s4 = "\\hensss.lst" ascii
      $s5 = "STUB32.EXE" fullword wide
      $s6 = "STUB.EXE" fullword wide
      $s8 = "\\ws2check.exe" ascii
      $s9 = "\\trojans.lst" ascii
      $s10 = "1996 InstallShield Software Corporation" fullword wide
   condition:
      all of them
}