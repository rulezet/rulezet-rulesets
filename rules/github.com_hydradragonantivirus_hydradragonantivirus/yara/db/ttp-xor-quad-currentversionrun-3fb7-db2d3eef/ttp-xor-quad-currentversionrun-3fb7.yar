rule TTP_XOR_QUAD_CurrentVersionRun_3fb7 {
  strings:
    $key_3fb7 = { 6c d8 [2] 48 d6 [2] 63 fa [2] 4d d8 [2] 59 c3 [2] 56 d9 [2] 48 c4 [2] 4a c5 [2] 51 c3 [2] 4d c4 [2] 51 eb }

  condition:
    any of them
}