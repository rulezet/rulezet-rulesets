rule EquationGroup_Toolset_Apr17_Architouch_1_0_0_RID37AE : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 17:48:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "444979a2387530c8fbbc5ddb075b15d6a4717c3435859955f37ebc0f40a4addc"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "[+] Target is %s" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 300KB and all of them )
}