rule EquationGroup_nethide_Lp_RID30BF : APT DEMO EXE FILE {
   meta:
      description = "EquationGroup Malware - file nethide_Lp.dll"
      author = "Florian Roth"
      reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/messagefinale/"
      date = "2017-01-13 12:53:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "137749c0fbb8c12d1a650f0bfc73be2739ff084165d02e4cb68c6496d828bf1d"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Error: Attempt to hide all TCP connections (any:any)." fullword wide
      $x2 = "privilegeRunInKernelMode failed" fullword wide
      $x3 = "Failed to unhide requested connection" fullword wide
      $x4 = "Nethide running in USER_MODE" fullword wide
      $x5 = "Not enough slots for all of the list.  Some entries may have not been hidden." fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 300KB and 1 of them ) or ( all of them )
}