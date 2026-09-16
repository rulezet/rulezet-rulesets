rule EquationGroup_Toolset_Apr17_renamer {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "9c30331cb00ae8f417569e9eb2c645ebbb36511d2d1531bb8d06b83781dfe3ac"
      id = "b5a7c8a8-c30d-5667-a458-6962a24061d3"
   strings:
      $s1 = "FILE_NAME_CONVERSION.LOG" fullword wide
      $s2 = "Log file exists. You must delete it!!!" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 80KB and all of them )
}