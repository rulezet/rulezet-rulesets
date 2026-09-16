rule EquationGroup_Toolset_Apr17_SetCallbackPorts_RID3847 : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 18:14:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "16f66c2593665c2507a78f96c0c2a9583eab0bda13a639e28f550c92f9134ff0"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "USAGE: %s <input file> <output file> <port1> [port2] [port3] [port4] [port5] [port6]" fullword ascii
      $s2 = "You may enter between 1 and 6 ports to change the defaults." fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 100KB and 1 of them )
}