rule EquationGroup_Toolset_Apr17__SendCFTrigger_SendPKTrigger_6_RID3D29 : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 21:42:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "3bee31b9edca8aa010a4684c2806b0ca988b2bcc14ad0964fec4f11f3f6fb748"
      hash2 = "2f9c7a857948795873a61f4d4f08e1bd0a41e3d6ffde212db389365488fa6e26"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s4 = "* Failed to connect to destination - %u" fullword wide
      $s6 = "* Failed to convert destination address into sockaddr_storage values" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 400KB and 1 of them )
}