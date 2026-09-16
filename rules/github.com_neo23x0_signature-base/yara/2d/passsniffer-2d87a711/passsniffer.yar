rule PassSniffer {
   meta:
      description = "Disclosed hacktool set (old stuff) - file PassSniffer.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "23.11.14"
      score = 60
      hash = "dcce4c577728e8edf7ed38ac6ef6a1e68afb2c9f"
      id = "f5965aa8-0f78-56fd-8e3e-6dc013942cb3"
   strings:
      $s2 = "Sniff" fullword ascii
      $s3 = "GetLas" fullword ascii
      $s4 = "VersionExA" fullword ascii
      $s10 = " Only RuntUZ" fullword ascii
      $s12 = "emcpysetprintf\\" ascii
      $s13 = "WSFtartup" fullword ascii
   condition:
      all of them
}