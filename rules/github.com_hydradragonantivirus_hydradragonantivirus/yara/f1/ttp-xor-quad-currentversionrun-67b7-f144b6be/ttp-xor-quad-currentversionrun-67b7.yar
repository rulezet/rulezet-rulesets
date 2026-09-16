rule TTP_XOR_QUAD_CurrentVersionRun_67b7 {
  strings:
    $key_67b7 = { 34 d8 [2] 10 d6 [2] 3b fa [2] 15 d8 [2] 01 c3 [2] 0e d9 [2] 10 c4 [2] 12 c5 [2] 09 c3 [2] 15 c4 [2] 09 eb }

  condition:
    any of them
}