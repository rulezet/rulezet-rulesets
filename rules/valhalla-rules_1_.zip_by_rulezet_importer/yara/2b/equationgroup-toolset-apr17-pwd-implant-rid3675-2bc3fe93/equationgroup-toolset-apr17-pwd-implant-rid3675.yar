rule EquationGroup_Toolset_Apr17_pwd_Implant_RID3675 : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 16:56:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "ee72ac76d82dfec51c8fbcfb5fc99a0a45849a4565177e01d8d23a358e52c542"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "7\"7(7/7>7O7]7o7w7" fullword ascii
      $op1 = { 40 50 89 44 24 18 FF 15 34 20 00 } 
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 20KB and 1 of them )
}