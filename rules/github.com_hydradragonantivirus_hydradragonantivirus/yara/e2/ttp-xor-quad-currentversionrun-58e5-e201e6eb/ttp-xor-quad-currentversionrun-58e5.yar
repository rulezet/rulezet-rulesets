rule TTP_XOR_QUAD_CurrentVersionRun_58e5 {
  strings:
    $key_58e5 = { 0b 8a [2] 2f 84 [2] 04 a8 [2] 2a 8a [2] 3e 91 [2] 31 8b [2] 2f 96 [2] 2d 97 [2] 36 91 [2] 2a 96 [2] 36 b9 }

  condition:
    any of them
}