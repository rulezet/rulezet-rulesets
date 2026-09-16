rule EquationGroup_Toolset_Apr17_Regread_1_1_1_RID3660 : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 16:53:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "722f034ba634f45c429c7dafdbff413c08976b069a6b30ec91bfa5ce2e4cda26"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "[+] Connected to the Registry Service" fullword ascii
      $s2 = "f08d49ac41d1023d9d462d58af51414daff95a6a" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 80KB and 1 of them )
}