rule EquationGroup_PortMap_Lp_RID30A1 : APT DEMO EXE FILE {
   meta:
      description = "EquationGroup Malware - file PortMap_Lp.dll"
      author = "Florian Roth"
      reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/messagefinale/"
      date = "2017-01-13 12:48:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "2b27f2faae9de6330f17f60a1d19f9831336f57fdfef06c3b8876498882624a6"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Privilege elevation failed" fullword wide
      $s2 = "Portmap ended due to max number of ports" fullword wide
      $s3 = "Invalid parameters received for portmap" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 300KB and 2 of them )
}