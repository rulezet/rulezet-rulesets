rule EquationGroup_curseyo_win2k_v_1_0_0 {
   meta:
      description = "Equation Group hack tool set"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09"
      hash1 = "5dc77614764b23a38610fdd8abe5b2274222f206889e4b0974a3fea569055ed6"
      id = "8161907d-d6bd-58c5-806d-387321b93b21"
   strings:
      $s1 = "0123456789abcdefABCEDF:" fullword ascii

      $op0 = { c6 06 5b 8b bd 70 ff ff ff 8b 9d 64 ff ff ff 0f } 
      $op1 = { 55 b8 ff ff ff ff 89 e5 83 ec 28 89 7d fc 8b 7d } 
      $op2 = { ff 05 10 64 41 00 89 34 24 e8 df 1e 00 00 e9 31 } 
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and all of them )
}