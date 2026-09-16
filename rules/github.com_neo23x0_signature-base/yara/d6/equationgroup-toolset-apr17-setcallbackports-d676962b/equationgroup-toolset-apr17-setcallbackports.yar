rule EquationGroup_Toolset_Apr17_SetCallbackPorts {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "16f66c2593665c2507a78f96c0c2a9583eab0bda13a639e28f550c92f9134ff0"
      id = "3c06fc74-2e75-5348-bb62-30c724de1414"
   strings:
      $s1 = "USAGE: %s <input file> <output file> <port1> [port2] [port3] [port4] [port5] [port6]" fullword ascii
      $s2 = "You may enter between 1 and 6 ports to change the defaults." fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and 1 of them )
}