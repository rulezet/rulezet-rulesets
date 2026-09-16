rule TTP_XOR_QUAD_CurrentVersionRun_7bb7 {
  strings:
    $key_7bb7 = { 28 d8 [2] 0c d6 [2] 27 fa [2] 09 d8 [2] 1d c3 [2] 12 d9 [2] 0c c4 [2] 0e c5 [2] 15 c3 [2] 09 c4 [2] 15 eb }

  condition:
    any of them
}