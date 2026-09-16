rule EquationGroup_Toolset_Apr17_SetResourceName_RID37EB : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 17:59:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "537793d5158aecd0debae25416450bd885725adfc8ca53b0577a3df4b0222e2e"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Updates the name of the dll or executable in the resource file" fullword ascii
      $x2 = "*NOTE: SetResourceName does not work with PeddleCheap versions" fullword ascii
      $x3 = "2 = [appinit.dll] level4 dll" fullword ascii
      $x4 = "1 = [spcss32.exe] level3 exe" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 100KB and 1 of them )
}