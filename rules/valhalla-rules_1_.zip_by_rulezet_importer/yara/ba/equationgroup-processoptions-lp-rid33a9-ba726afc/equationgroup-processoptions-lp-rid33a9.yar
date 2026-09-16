rule EquationGroup_ProcessOptions_Lp_RID33A9 : APT DEMO EXE FILE {
   meta:
      description = "EquationGroup Malware - file ProcessOptions_Lp.dll"
      author = "Florian Roth"
      reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/messagefinale/"
      date = "2017-01-13 14:57:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "31d86f77137f0b3697af03dd28d6552258314cecd3c1d9dc18fcf609eb24229a"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Invalid parameter received by implant" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 300KB and all of them )
}