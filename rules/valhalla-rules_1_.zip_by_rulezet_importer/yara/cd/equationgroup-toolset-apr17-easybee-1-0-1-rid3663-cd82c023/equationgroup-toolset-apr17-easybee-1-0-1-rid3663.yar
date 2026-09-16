rule EquationGroup_Toolset_Apr17_Easybee_1_0_1_RID3663 : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 16:53:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "59c17d6cb564edd32c770cd56b5026e4797cf9169ff549735021053268b31611"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "@@for /f \"delims=\" %%i in ('findstr /smc:\"%s\" *.msg') do if not \"%%MsgFile1%%\"==\"%%i\" del /f \"%%i\"" fullword ascii
      $x2 = "Logging out of WebAdmin (as target account)" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 200KB and 1 of them )
}