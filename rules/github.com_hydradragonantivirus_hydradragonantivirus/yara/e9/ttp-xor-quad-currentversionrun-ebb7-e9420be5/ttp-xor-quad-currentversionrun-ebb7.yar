rule TTP_XOR_QUAD_CurrentVersionRun_ebb7 {
  strings:
    $key_ebb7 = { b8 d8 [2] 9c d6 [2] b7 fa [2] 99 d8 [2] 8d c3 [2] 82 d9 [2] 9c c4 [2] 9e c5 [2] 85 c3 [2] 99 c4 [2] 85 eb }

  condition:
    any of them
}