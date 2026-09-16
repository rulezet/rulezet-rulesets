rule TTP_XOR_QUAD_CurrentVersionRun_dfb7 {
  strings:
    $key_dfb7 = { 8c d8 [2] a8 d6 [2] 83 fa [2] ad d8 [2] b9 c3 [2] b6 d9 [2] a8 c4 [2] aa c5 [2] b1 c3 [2] ad c4 [2] b1 eb }

  condition:
    any of them
}