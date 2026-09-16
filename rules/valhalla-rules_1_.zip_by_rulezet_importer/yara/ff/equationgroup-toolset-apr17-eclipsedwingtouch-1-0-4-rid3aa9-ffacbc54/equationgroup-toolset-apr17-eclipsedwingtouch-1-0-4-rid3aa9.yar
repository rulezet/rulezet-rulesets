rule EquationGroup_Toolset_Apr17_Eclipsedwingtouch_1_0_4_RID3AA9 : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 19:56:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "46da99d80fc3eae5d1d5ab2da02ed7e61416e1eafeb23f37b180c46e9eff8a1c"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "[-] The target is NOT vulnerable" fullword ascii
      $x2 = "[+] The target IS VULNERABLE" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 50KB and 1 of them )
}