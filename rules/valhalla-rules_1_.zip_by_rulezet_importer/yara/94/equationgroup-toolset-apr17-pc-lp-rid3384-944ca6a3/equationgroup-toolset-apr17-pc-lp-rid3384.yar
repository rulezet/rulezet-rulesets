rule EquationGroup_Toolset_Apr17_PC_LP_RID3384 : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 14:51:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "3a505c39acd48a258f4ab7902629e5e2efa8a2120a4148511fe3256c37967296"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "* Failed to get connection information.  Aborting launcher!" fullword wide
      $s2 = "Format: <command> <target port> [lp port]" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 200KB and all of them )
}