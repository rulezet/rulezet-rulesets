rule TTP_XOR_QUAD_CurrentVersionRun_5fb7 {
  strings:
    $key_5fb7 = { 0c d8 [2] 28 d6 [2] 03 fa [2] 2d d8 [2] 39 c3 [2] 36 d9 [2] 28 c4 [2] 2a c5 [2] 31 c3 [2] 2d c4 [2] 31 eb }

  condition:
    any of them
}