rule EquationGroup_Toolset_Apr17_greatdoc_dll_config {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "fd9d0abfa727784dd07562656967d220286fc0d63bcf7e2c35d4c02bc2e5fc2e"
      id = "592e4e40-f5cd-5a11-8a1b-0cdcf6f267ec"
   strings:
      $x1 = "C:\\Projects\\GREATERDOCTOR\\trunk\\GREATERDOCTOR" ascii
      $x2 = "src\\build\\Release\\dllConfig\\dllConfig.pdb" ascii
      $x3 = "GREATERDOCTOR [ commandline args configuration ]" fullword ascii
      $x4 = "-useage: <scanner> \"<cmdline args>\"" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and 1 of them )
}