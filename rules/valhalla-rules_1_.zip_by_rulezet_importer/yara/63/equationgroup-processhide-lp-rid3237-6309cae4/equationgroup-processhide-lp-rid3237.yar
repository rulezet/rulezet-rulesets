rule EquationGroup_ProcessHide_Lp_RID3237 : APT DEMO EXE FILE {
   meta:
      description = "EquationGroup Malware - file ProcessHide_Lp.dll"
      author = "Florian Roth"
      reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/messagefinale/"
      date = "2017-01-13 13:55:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "cdee0daa816f179e74c90c850abd427fbfe0888dcfbc38bf21173f543cdcdc66"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Invalid flag.  Can only hide or unhide" fullword wide
      $x2 = "Process elevation failed" fullword wide
      $x3 = "Unknown error hiding process" fullword wide
      $x4 = "Invalid process links found in EPROCESS" fullword wide
      $x5 = "Unable to find SYSTEM process" fullword wide
      $x6 = "Process hidden, but EPROCESS location lost" fullword wide
      $x7 = "Invalid EPROCESS location for given ID" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 300KB and 1 of them ) or ( 3 of them )
}