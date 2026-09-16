rule EquationGroup_cursetingle_2_0_1_2_mswin32_v_2_0_1 {
   meta:
      description = "Equation Group hack tool set"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09"
      hash1 = "614bf159b956f20d66cedf25af7503b41e91841c75707af0cdf4495084092a61"
      id = "7a1870ba-d600-5c11-8d3d-41395ad8be63"
   strings:
      $s1 = "[%.2u%.2u%.2u%.2u%.2u%.2u]" fullword ascii
      $s2 = "0123456789abcdefABCEDF:" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and all of them )
}