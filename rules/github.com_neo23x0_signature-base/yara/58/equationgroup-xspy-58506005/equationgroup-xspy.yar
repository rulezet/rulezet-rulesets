rule EquationGroup_xspy {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file xspy"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "841e065c9c340a1e522b281a39753af8b6a3db5d9e7d8f3d69e02fdbd662f4cf"
      id = "fcb7246a-d613-51d7-a4f7-f767fa5f79e1"
   strings:
      $s1 = "USAGE: xspy -display <display> -delay <usecs> -up" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 60KB and all of them )
}