rule TTP_XOR_QUAD_CurrentVersionRun_25b7 {
  strings:
    $key_25b7 = { 76 d8 [2] 52 d6 [2] 79 fa [2] 57 d8 [2] 43 c3 [2] 4c d9 [2] 52 c4 [2] 50 c5 [2] 4b c3 [2] 57 c4 [2] 4b eb }

  condition:
    any of them
}