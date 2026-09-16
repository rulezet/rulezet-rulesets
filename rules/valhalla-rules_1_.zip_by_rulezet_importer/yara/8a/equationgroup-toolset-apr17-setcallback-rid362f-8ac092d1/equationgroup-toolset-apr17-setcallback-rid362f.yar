rule EquationGroup_Toolset_Apr17_SetCallback_RID362F : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 16:45:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "a8854f6b01d0e49beeb2d09e9781a6837a0d18129380c6e1b1629bc7c13fdea2"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "*NOTE: This version of SetCallback does not work with PeddleCheap versions prior" fullword ascii
      $s3 = "USAGE: SetCallback <input file> <output file>" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 100KB and all of them )
}