rule EquationGroup_Toolset_Apr17_Englishmansdentist_1_2_0_RID3B1A : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 20:14:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "2a6ab28885ad7d5d64ac4c4fb8c619eca3b7fb3be883fc67c90f3ea9251f34c6"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "[+] CheckCredentials(): Checking to see if valid username/password" fullword ascii
      $x2 = "Error connecting to target, TbMakeSocket() %s:%d." fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 200KB and 1 of them )
}