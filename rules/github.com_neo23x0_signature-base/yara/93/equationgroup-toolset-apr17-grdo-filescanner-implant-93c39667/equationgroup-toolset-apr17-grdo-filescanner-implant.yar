rule EquationGroup_Toolset_Apr17_GrDo_FileScanner_Implant {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      modified = "2023-01-06"
      hash1 = "8d2e43567e1360714c4271b75c21a940f6b26a789aa0fce30c6478ae4ac587e4"
      id = "79a3cc02-0cda-59e2-8698-29a6cb0a3061"
   strings:
      $s1 = "system32\\winsrv.dll" fullword wide
      $s2 = "raw_open CreateFile error" fullword ascii
      $s3 = "\\dllcache\\" wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 400KB and all of them )
}