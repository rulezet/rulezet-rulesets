rule EquationGroup_Toolset_Apr17_Esteemaudittouch_2_1_0 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "f6b9caf503bb664b22c6d39c87620cc17bdb66cef4ccfa48c31f2a3ae13b4281"
      id = "bb66245e-1261-50bd-8666-75fc4c52ad84"
   strings:
      $x1 = "[-] Touching the target failed!" fullword ascii
      $x2 = "[-] OS fingerprint not complete - 0x%08x!" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and 1 of them )
}