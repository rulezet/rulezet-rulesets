rule EquationGroup_Toolset_Apr17_SendPKTrigger {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "2f9c7a857948795873a61f4d4f08e1bd0a41e3d6ffde212db389365488fa6e26"
      id = "6cbf95eb-323c-53a3-9aca-222626add4dc"
   strings:
      $x1 = "----====**** PORT KNOCK TRIGGER BEGIN ****====----" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and all of them )
}