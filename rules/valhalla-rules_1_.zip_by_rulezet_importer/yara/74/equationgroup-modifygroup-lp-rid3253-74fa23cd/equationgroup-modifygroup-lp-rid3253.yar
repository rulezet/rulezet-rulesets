rule EquationGroup_ModifyGroup_Lp_RID3253 : APT DEMO EXE FILE {
   meta:
      description = "EquationGroup Malware - file ModifyGroup_Lp.dll"
      author = "Florian Roth"
      reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/messagefinale/"
      date = "2017-01-13 14:00:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "dfb38ed2ca3870faf351df1bd447a3dc4470ed568553bf83df07bf07967bf520"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Modify Privileges failed" fullword wide
      $s2 = "Given privilege name not found" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 300KB and all of them )
}