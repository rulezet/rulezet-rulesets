rule EquationGroup_Toolset_Apr17_DiBa_Target_BH_2000 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "0654b4b8727488769390cd091029f08245d690dd90d1120e8feec336d1f9e788"
      id = "b02fa407-e6f1-5c2d-a587-7edb55dbe0a5"
   strings:
      $s2 = "0M1U1Z1p1" fullword ascii 
      $s14 = "SPRQWV" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and all of them )
}