rule EquationGroup_RunAsChild_Lp_RID31AB : APT DEMO EXE FILE {
   meta:
      description = "EquationGroup Malware - file RunAsChild_Lp.dll"
      author = "Florian Roth"
      reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/messagefinale/"
      date = "2017-01-13 13:32:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "1097e1d562341858e241f1f67788534c0e340a2dc2e75237d57e3f473e024464"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Privilege elevation failed" fullword wide
      $s2 = "Unable to open parent process" fullword wide
      $s4 = "Invalid input to lpRunAsChildPPC" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 300KB and all of them )
}