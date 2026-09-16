rule EquationGroup_Toolset_Apr17_SetOurAddr {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "04ccc060d401ddba674371e66e0288ebdbfa7df74b925c5c202109f23fb78504"
      id = "a2dbfa7b-3fb6-56cf-9391-1a3abb08e3cb"
   strings:
      $s1 = "USAGE: SetOurAddr <input file> <output file> <protocol> [IP/IPX address]" fullword ascii
      $s2 = "Replaced default IP address (127.0.0.1) with Local IP Address %d.%d.%d.%d" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and 1 of them )
}