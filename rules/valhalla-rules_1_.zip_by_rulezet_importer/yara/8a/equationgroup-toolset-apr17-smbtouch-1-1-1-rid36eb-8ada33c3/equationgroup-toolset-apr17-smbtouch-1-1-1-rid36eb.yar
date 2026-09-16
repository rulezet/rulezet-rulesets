rule EquationGroup_Toolset_Apr17_Smbtouch_1_1_1_RID36EB : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 17:16:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "108243f61c53f00f8f1adcf67c387a8833f1a2149f063dd9ef29205c90a3c30a"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "[+] Target is vulnerable to %d exploit%s" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 400KB and all of them )
}