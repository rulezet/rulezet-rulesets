rule EquationGroup_Toolset_Apr17_renamer_RID34E0 : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 15:49:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "9c30331cb00ae8f417569e9eb2c645ebbb36511d2d1531bb8d06b83781dfe3ac"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "FILE_NAME_CONVERSION.LOG" fullword wide
      $s2 = "Log file exists. You must delete it!!!" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 80KB and all of them )
}