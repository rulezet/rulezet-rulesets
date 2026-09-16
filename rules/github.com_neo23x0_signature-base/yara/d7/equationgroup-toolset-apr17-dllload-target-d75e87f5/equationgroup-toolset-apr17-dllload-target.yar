rule EquationGroup_Toolset_Apr17_DllLoad_Target {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "a42d5201af655e43cefef30d7511697e6faa2469dc4a74bc10aa060b522a1cf5"
      id = "9def0814-c86a-5fae-abc2-4185596a74aa"
   strings:
      $s1 = "BzWKJD+" fullword ascii

      $op1 = { 44 24 6c 6c 88 5c 24 6d }
      $op2 = { 44 24 54 63 c6 44 24 55 74 c6 44 24 56 69 }
      $op3 = { 44 24 5c 6c c6 44 24 5d 65 c6 44 24 5e }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and all of them )
}