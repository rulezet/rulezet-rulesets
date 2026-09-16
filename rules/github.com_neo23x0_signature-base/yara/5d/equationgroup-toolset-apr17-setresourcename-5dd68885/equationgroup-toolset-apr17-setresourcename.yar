rule EquationGroup_Toolset_Apr17_SetResourceName {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "537793d5158aecd0debae25416450bd885725adfc8ca53b0577a3df4b0222e2e"
      id = "dc261147-3b52-57c3-9729-2645a0999a99"
   strings:
      $x1 = "Updates the name of the dll or executable in the resource file" fullword ascii
      $x2 = "*NOTE: SetResourceName does not work with PeddleCheap versions" fullword ascii
      $x3 = "2 = [appinit.dll] level4 dll" fullword ascii
      $x4 = "1 = [spcss32.exe] level3 exe" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and 1 of them )
}