rule EquationGroup_Toolset_Apr17_PC_Level_Generic_RID37FC : APT DEMO EXE FILE GEN {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 18:01:51"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "7a6488dd13936e505ec738dcc84b9fec57a5e46aab8aff59b8cfad8f599ea86a"
      hash2 = "0e3cfd48732d0b301925ea3ec6186b62724ec755ed40ed79e7cd6d3df511b8a0"
      hash3 = "d1d6e3903b6b92cc52031c963e2031b5956cadc29cc8b3f2c8f38be20f98a4a7"
      tags = "APT, DEMO, EXE, FILE, GEN"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "wshtcpip.WSHGetSocketInformation" fullword ascii
      $s2 = "\\\\.\\%hs" fullword ascii
      $s3 = ".?AVResultIp@Mini_Mcl_Cmd_NetConnections@@" fullword ascii
      $s4 = "Corporation. All rights reserved." fullword wide
      $s5 = { 49 83 3c 24 00 75 02 eb 5d 49 8b 34 24 0f b7 46 } 
      $op1 = { 44 24 57 6f c6 44 24 58 6e c6 44 24 59 } 
      $op2 = { c6 44 24 56 64 88 5c 24 57 } 
      $op3 = { 44 24 6d 4c c6 44 24 6e 6f c6 44 24 6f } 
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 400KB and ( 2 of ( $s* ) or all of ( $op* ) )
}