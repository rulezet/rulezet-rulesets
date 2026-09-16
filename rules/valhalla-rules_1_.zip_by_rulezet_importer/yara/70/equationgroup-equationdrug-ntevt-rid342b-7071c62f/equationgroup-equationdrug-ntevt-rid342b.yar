rule EquationGroup_EquationDrug_ntevt_RID342B : APT DEMO EXE FILE {
   meta:
      description = "EquationGroup Malware - file ntevt.sys"
      author = "Florian Roth"
      reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/messagefinale/"
      date = "2017-01-13 15:19:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "45e5e1ea3456d7852f5c610c7f4447776b9f15b56df7e3a53d57996123e0cebf"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "ntevt.sys" fullword ascii
      $s2 = "c:\\ntevt.pdb" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 500KB and all of them )
}