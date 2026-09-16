rule EquationGroup_Toolset_Apr17_yak_min_install {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "f67214083d60f90ffd16b89a0ce921c98185b2032874174691b720514b1fe99e"
      id = "dc648deb-4220-5ec3-b95f-ff6cc463f79b"
   strings:
      $s1 = "driver start" fullword ascii
      $s2 = "DeviceIoControl Error: %d" fullword ascii
      $s3 = "Phlook" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and all of them )
}