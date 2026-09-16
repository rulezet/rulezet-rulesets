rule TTP_XOR_QUAD_CurrentVersionRun_13b7 {
  strings:
    $key_13b7 = { 40 d8 [2] 64 d6 [2] 4f fa [2] 61 d8 [2] 75 c3 [2] 7a d9 [2] 64 c4 [2] 66 c5 [2] 7d c3 [2] 61 c4 [2] 7d eb }

  condition:
    any of them
}