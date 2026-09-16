rule EquationGroup_Toolset_Apr17_svctouch_RID3565 : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 16:11:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "96b6a3c4f53f9e7047aa99fd949154745e05dc2fd2eb21ef6f0f9b95234d516b"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Causes: Firewall,Machine down,DCOM disabled\\not supported,etc." fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 10KB and 1 of them )
}