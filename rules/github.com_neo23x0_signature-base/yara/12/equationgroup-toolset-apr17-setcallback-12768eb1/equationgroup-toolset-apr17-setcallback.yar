rule EquationGroup_Toolset_Apr17_SetCallback {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "a8854f6b01d0e49beeb2d09e9781a6837a0d18129380c6e1b1629bc7c13fdea2"
      id = "3c06fc74-2e75-5348-bb62-30c724de1414"
   strings:
      $s2 = "*NOTE: This version of SetCallback does not work with PeddleCheap versions prior" fullword ascii
      $s3 = "USAGE: SetCallback <input file> <output file>" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and all of them )
}