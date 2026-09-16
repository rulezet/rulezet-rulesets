rule EquationGroup_Toolset_Apr17__SendCFTrigger_SendPKTrigger_6 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      super_rule = 1
      hash1 = "3bee31b9edca8aa010a4684c2806b0ca988b2bcc14ad0964fec4f11f3f6fb748"
      hash2 = "2f9c7a857948795873a61f4d4f08e1bd0a41e3d6ffde212db389365488fa6e26"
      id = "658d6f7d-2164-5e43-b5a5-d9bea9cd2e27"
   strings:
      $s4 = "* Failed to connect to destination - %u" fullword wide
      $s6 = "* Failed to convert destination address into sockaddr_storage values" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 400KB and 1 of them )
}