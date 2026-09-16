rule TTP_XOR_QUAD_CurrentVersionRun_7fb7 {
  strings:
    $key_7fb7 = { 2c d8 [2] 08 d6 [2] 23 fa [2] 0d d8 [2] 19 c3 [2] 16 d9 [2] 08 c4 [2] 0a c5 [2] 11 c3 [2] 0d c4 [2] 11 eb }

  condition:
    any of them
}