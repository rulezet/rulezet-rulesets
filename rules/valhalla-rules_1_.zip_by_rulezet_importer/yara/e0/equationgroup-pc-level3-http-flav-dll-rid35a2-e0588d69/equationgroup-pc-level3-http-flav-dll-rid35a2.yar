rule EquationGroup_PC_Level3_http_flav_dll_RID35A2 : APT DEMO EXE FILE {
   meta:
      description = "EquationGroup Malware - file PC_Level3_http_flav_dll"
      author = "Florian Roth"
      reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/messagefinale/"
      date = "2017-01-13 16:21:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "27972d636b05a794d17cb3203d537bcf7c379fafd1802792e7fb8e72f130a0c4"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Psxssdll.dll" fullword wide
      $s2 = "Posix Server Dll" fullword wide
      $s4 = "itanium" fullword wide
      $s5 = "RHTTP/1.0" fullword wide
      $s8 = "Copyright (C) Microsoft" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 300KB and all of them )
}