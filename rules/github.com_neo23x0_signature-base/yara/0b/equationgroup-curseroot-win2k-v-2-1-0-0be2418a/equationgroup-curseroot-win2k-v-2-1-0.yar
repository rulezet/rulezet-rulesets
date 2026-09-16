rule EquationGroup_curseroot_win2k_v_2_1_0 {
   meta:
      description = "Equation Group hack tool set"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09"
      hash1 = "a1637948ed6ebbd2e582eb99df0c06b27a77c01ad1779b3d84c65953ca2cb603"
      id = "bd2257ef-8170-547d-9c5e-7ff03404495c"
   strings:
      $s1 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/%s,%s" fullword ascii
      $op0 = { c7 44 24 04 ff ff ff ff 89 04 24 e8 46 65 01 00 } 
      $op1 = { 8d 5d 88 89 1c 24 e8 24 1b 01 00 be ff ff ff ff } 
      $op2 = { d3 e0 48 e9 0c ff ff ff 8b 45 } 
   condition:
      ( uint16(0) == 0x5a4d and filesize < 400KB and $s1 and 2 of ($op*) )
}