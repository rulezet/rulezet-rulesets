rule EquationGroup_tnmunger {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file tnmunger"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "1ab985d84871c54d36ba4d2abd9168c2a468f1ba06994459db06be13ee3ae0d2"
      id = "c95dd24f-ffc9-5e58-aed7-205daa001b8c"
   strings:
      $s1 = "TEST: mungedport=%6d  pp=%d  unmunged=%6d" fullword ascii
      $s2 = "mungedport=%6d  pp=%d  unmunged=%6d" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 10KB and 1 of them )
}