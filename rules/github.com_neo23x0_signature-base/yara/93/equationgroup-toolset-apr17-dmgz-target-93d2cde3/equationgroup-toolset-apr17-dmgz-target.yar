rule EquationGroup_Toolset_Apr17_DmGz_Target {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "5964966041f93d5d0fb63ce4a85cf9f7a73845065e10519b0947d4a065fdbdf2"
      id = "182a2488-ac3f-5dc6-aa61-d6d267574d10"
   strings:
      $s1 = "\\\\.\\%ls" fullword ascii
      $s3 = "6\"6<6C6H6M6Z6f6t6" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 80KB and all of them )
}