rule EquationGroup_EquationDrug_Gen_6_RID33A9 : APT DEMO EXE FILE GEN {
   meta:
      description = "EquationGroup Malware - file PC_Level3_dll_x64"
      author = "Florian Roth"
      reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/messagefinale/"
      date = "2017-01-13 14:57:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "339855618fb3ef53987b8c14a61bd4519b2616e766149e0c21cbd7cbe7a632c9"
      tags = "APT, DEMO, EXE, FILE, GEN"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Psxssdll.dll" fullword wide
      $s2 = "Posix Server Dll" fullword wide
      $s3 = "Copyright (C) Microsoft" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 300KB and all of them )
}