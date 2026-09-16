rule EquationGroup_EquationDrug_Gen_5_RID33A8 : APT DEMO EXE FILE GEN {
   meta:
      description = "EquationGroup Malware - file PC_Level3_http_dll"
      author = "Florian Roth"
      reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/messagefinale/"
      date = "2017-01-13 14:57:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "4ebfc1f6ec6a0e68e47e5b231331470a4483184cf715a578191b91ba7c32094d"
      tags = "APT, DEMO, EXE, FILE, GEN"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Psxssdll.dll" fullword wide
      $s2 = "Posix Server Dll" fullword wide
      $s3 = "itanium" fullword wide
      $s6 = "Copyright (C) Microsoft" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 300KB and all of them )
}