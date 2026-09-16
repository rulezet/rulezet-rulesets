rule EquationGroup_cryptTool {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file cryptTool"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "96947ad30a2ab15ca5ef53ba8969b9d9a89c48a403e8b22dd5698145ac6695d2"
      id = "e1f4e010-9c42-5b8a-8feb-2885b99307fe"
   strings:
      $s1 = "The encryption key is " fullword ascii
      $s2 = "___tempFile2.out" ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 200KB and all of them )
}