rule EquationGroup_modifyAuthentication_Implant_RID383F : APT DEMO EXE FILE {
   meta:
      description = "EquationGroup Malware - file modifyAuthentication_Implant.dll"
      author = "Florian Roth"
      reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/messagefinale/"
      date = "2017-01-13 18:13:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "e1dff24af5bfc991dca21b4e3a19ffbc069176d674179eef691afc6b1ac6f805"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "LSASS.EXE" fullword wide
      $s2 = "hsamsrv.dll" fullword ascii
      $s3 = "hZwOpenProcess" fullword ascii
      $s4 = "hOpenProcess" fullword ascii
      $s5 = ".?AVFeFinallyFailure@@" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 200KB and all of them )
}