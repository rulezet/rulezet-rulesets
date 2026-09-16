rule EquationGroup_tnmunger_RID3033 : APT DEMO FILE G0020 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file tnmunger"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08 12:29:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "1ab985d84871c54d36ba4d2abd9168c2a468f1ba06994459db06be13ee3ae0d2"
      tags = "APT, DEMO, FILE, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "TEST: mungedport=%6d  pp=%d  unmunged=%6d" fullword ascii
      $s2 = "mungedport=%6d  pp=%d  unmunged=%6d" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and filesize < 10KB and 1 of them )
}