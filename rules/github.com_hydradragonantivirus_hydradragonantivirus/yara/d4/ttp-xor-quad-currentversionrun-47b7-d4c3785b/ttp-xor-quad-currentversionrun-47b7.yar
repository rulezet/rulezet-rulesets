rule TTP_XOR_QUAD_CurrentVersionRun_47b7 {
  strings:
    $key_47b7 = { 14 d8 [2] 30 d6 [2] 1b fa [2] 35 d8 [2] 21 c3 [2] 2e d9 [2] 30 c4 [2] 32 c5 [2] 29 c3 [2] 35 c4 [2] 29 eb }

  condition:
    any of them
}