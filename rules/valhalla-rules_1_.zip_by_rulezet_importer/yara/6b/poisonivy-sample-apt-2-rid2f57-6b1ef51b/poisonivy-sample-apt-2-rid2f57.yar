rule PoisonIvy_Sample_APT_2_RID2F57 : APT DEMO EXE FILE {
   meta:
      description = "Detects a PoisonIvy Malware"
      author = "Florian Roth"
      reference = "VT Analysis"
      date = "2015-06-03 11:53:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "pidll.dll" fullword ascii
      $s1 = "sens32.dll" fullword wide
      $s2 = "9.0.1.56" fullword wide
      $s3 = "FileDescription" fullword wide
      $s4 = "OriginalFilename" fullword wide
      $s5 = "ZwSetInformationProcess" fullword ascii
      $s6 = "\"%=%14=" fullword ascii
      $s7 = "091A1G1R1_1g1u1z1" fullword ascii
      $s8 = "gHsMZz" fullword ascii
      $s9 = "Microsoft Media Device Service Provider" fullword wide
      $s10 = "Copyright (C) Microsoft Corp." fullword wide
      $s11 = "MFC42.DLL" fullword ascii
      $s12 = "MSVCRT.dll" fullword ascii
      $s13 = "SpecialBuild" fullword wide
      $s14 = "PrivateBuild" fullword wide
      $s15 = "Comments" fullword wide
      $s16 = "040904b0" fullword wide
      $s17 = "LegalTrademarks" fullword wide
      $s18 = "CreateThread" fullword ascii
      $s19 = "ntdll.dll" fullword ascii
      $s20 = "_adjust_fdiv" ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 47KB and all of them
}