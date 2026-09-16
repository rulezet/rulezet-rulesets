rule EquationGroup_exze {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file exze"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "1af6dde6d956db26c8072bf5ff26759f1a7fa792dd1c3498ba1af06426664876"
      id = "d452b952-0c4a-501b-93f5-064d13f2c08e"
   strings:
      $s1 = "shellFile" fullword ascii
      $s2 = "completed.1" fullword ascii
      $s3 = "zeke_remove" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 80KB and all of them )
}