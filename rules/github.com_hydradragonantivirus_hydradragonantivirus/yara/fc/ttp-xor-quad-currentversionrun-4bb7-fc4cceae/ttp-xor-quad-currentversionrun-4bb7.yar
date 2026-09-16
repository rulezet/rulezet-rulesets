rule TTP_XOR_QUAD_CurrentVersionRun_4bb7 {
  strings:
    $key_4bb7 = { 18 d8 [2] 3c d6 [2] 17 fa [2] 39 d8 [2] 2d c3 [2] 22 d9 [2] 3c c4 [2] 3e c5 [2] 25 c3 [2] 39 c4 [2] 25 eb }

  condition:
    any of them
}