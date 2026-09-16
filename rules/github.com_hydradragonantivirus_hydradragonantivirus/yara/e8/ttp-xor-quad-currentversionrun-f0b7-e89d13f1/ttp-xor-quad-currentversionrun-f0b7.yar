rule TTP_XOR_QUAD_CurrentVersionRun_f0b7 {
  strings:
    $key_f0b7 = { a3 d8 [2] 87 d6 [2] ac fa [2] 82 d8 [2] 96 c3 [2] 99 d9 [2] 87 c4 [2] 85 c5 [2] 9e c3 [2] 82 c4 [2] 9e eb }

  condition:
    any of them
}