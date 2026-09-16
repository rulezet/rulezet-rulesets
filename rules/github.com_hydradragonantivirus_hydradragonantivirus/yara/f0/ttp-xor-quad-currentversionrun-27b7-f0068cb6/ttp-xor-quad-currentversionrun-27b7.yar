rule TTP_XOR_QUAD_CurrentVersionRun_27b7 {
  strings:
    $key_27b7 = { 74 d8 [2] 50 d6 [2] 7b fa [2] 55 d8 [2] 41 c3 [2] 4e d9 [2] 50 c4 [2] 52 c5 [2] 49 c3 [2] 55 c4 [2] 49 eb }

  condition:
    any of them
}