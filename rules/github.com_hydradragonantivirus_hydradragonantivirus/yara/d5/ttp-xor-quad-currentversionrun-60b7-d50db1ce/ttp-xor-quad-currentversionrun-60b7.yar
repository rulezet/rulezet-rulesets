rule TTP_XOR_QUAD_CurrentVersionRun_60b7 {
  strings:
    $key_60b7 = { 33 d8 [2] 17 d6 [2] 3c fa [2] 12 d8 [2] 06 c3 [2] 09 d9 [2] 17 c4 [2] 15 c5 [2] 0e c3 [2] 12 c4 [2] 0e eb }

  condition:
    any of them
}