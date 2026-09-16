rule EquationGroup_PC_Level3_http_flav_dll_x64_RID36E3 : APT DEMO EXE FILE {
   meta:
      description = "EquationGroup Malware - file PC_Level3_http_flav_dll_x64"
      author = "Florian Roth"
      reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/messagefinale/"
      date = "2017-01-13 17:15:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "4e0209b4f5990148f5d6dee47dbc7021bf78a782b85cef4d6c8be22d698b884f"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Psxssdll.dll" fullword wide
      $s2 = "Posix Server Dll" fullword wide
      $s3 = ".?AVOpenSocket@@" fullword ascii
      $s4 = "RHTTP/1.0" fullword wide
      $s5 = "Copyright (C) Microsoft" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 400KB and ( all of ( $s* ) ) ) or ( all of them )
}