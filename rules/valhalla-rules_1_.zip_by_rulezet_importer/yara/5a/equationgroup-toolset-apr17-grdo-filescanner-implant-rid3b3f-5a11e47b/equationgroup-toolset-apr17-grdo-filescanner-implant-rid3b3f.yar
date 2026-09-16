rule EquationGroup_Toolset_Apr17_GrDo_FileScanner_Implant_RID3B3F : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 20:21:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-01-06"
      hash1 = "8d2e43567e1360714c4271b75c21a940f6b26a789aa0fce30c6478ae4ac587e4"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "system32\\winsrv.dll" fullword wide
      $s2 = "raw_open CreateFile error" fullword ascii
      $s3 = "\\dllcache\\" wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 400KB and all of them )
}