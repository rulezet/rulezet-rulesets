rule EquationGroup_cursehelper_win2k_i686_v_2_2_0 {
   meta:
      description = "Equation Group hack tool set"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09"
      hash1 = "5ac6fde8a06f4ade10d672e60e92ffbf78c4e8db6b5152e23171f6f53af0bfe1"
      id = "1c24aa6a-74ab-5832-876b-5cab43dc6bb7"
   strings:
      $s1 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/{}" fullword ascii

      $op1 = { 8d b5 48 ff ff ff 89 34 24 e8 56 2a 00 00 c7 44 } 
      $op2 = { e9 a2 f2 ff ff ff 85 b4 fe ff ff 8b 95 a8 fe ff } 
   condition:
      ( uint16(0) == 0x5a4d and filesize < 500KB and all of them )
}