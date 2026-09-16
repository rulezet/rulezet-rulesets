rule EquationGroup_EquationDrug_tdi6_RID3371 : APT DEMO EXE FILE {
   meta:
      description = "EquationGroup Malware - file tdi6.sys"
      author = "Florian Roth"
      reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/messagefinale/"
      date = "2017-01-13 14:48:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "12c082f74c0916a0e926488642236de3a12072a18d29c97bead15bb301f4b3f8"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "tdi6.sys" fullword wide
      $s3 = "TDI IPv6 Wrapper" fullword wide
      $s5 = "Corporation. All rights reserved." fullword wide
      $s6 = "FailAction" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 100KB and all of them )
}