rule TTP_XOR_QUAD_CurrentVersionRun_6db7 {
  strings:
    $key_6db7 = { 3e d8 [2] 1a d6 [2] 31 fa [2] 1f d8 [2] 0b c3 [2] 04 d9 [2] 1a c4 [2] 18 c5 [2] 03 c3 [2] 1f c4 [2] 03 eb }

  condition:
    any of them
}