rule TTP_XOR_QUAD_CurrentVersionRun_2ab7 {
  strings:
    $key_2ab7 = { 79 d8 [2] 5d d6 [2] 76 fa [2] 58 d8 [2] 4c c3 [2] 43 d9 [2] 5d c4 [2] 5f c5 [2] 44 c3 [2] 58 c4 [2] 44 eb }

  condition:
    any of them
}