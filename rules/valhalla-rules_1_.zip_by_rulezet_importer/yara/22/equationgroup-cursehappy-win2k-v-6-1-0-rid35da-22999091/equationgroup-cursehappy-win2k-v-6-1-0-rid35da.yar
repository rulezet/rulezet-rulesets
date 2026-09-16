rule EquationGroup_cursehappy_win2k_v_6_1_0_RID35DA : APT DEMO EXE FILE G0020 {
   meta:
      description = "Equation Group hack tool set"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09 16:30:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "eb669afd246a7ac4de79724abcce5bda38117b3138908b90cac58936520ea632"
      tags = "APT, DEMO, EXE, FILE, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $op1 = { e8 24 2c 01 00 85 c0 89 c6 ba ff ff ff ff 74 d6 } 
      $op2 = { 89 4c 24 04 89 34 24 89 44 24 08 e8 ce 49 ff ff } 
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 400KB and all of them )
}