rule EquationGroup_Toolset_Apr17_SetOurAddr_RID35D3 : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 16:29:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "04ccc060d401ddba674371e66e0288ebdbfa7df74b925c5c202109f23fb78504"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "USAGE: SetOurAddr <input file> <output file> <protocol> [IP/IPX address]" fullword ascii
      $s2 = "Replaced default IP address (127.0.0.1) with Local IP Address %d.%d.%d.%d" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 100KB and 1 of them )
}