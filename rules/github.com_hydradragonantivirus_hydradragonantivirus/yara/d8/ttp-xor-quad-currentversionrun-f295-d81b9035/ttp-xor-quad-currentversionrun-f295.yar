rule TTP_XOR_QUAD_CurrentVersionRun_f295 {
  strings:
    $key_f295 = { a1 fa [2] 85 f4 [2] ae d8 [2] 80 fa [2] 94 e1 [2] 9b fb [2] 85 e6 [2] 87 e7 [2] 9c e1 [2] 80 e6 [2] 9c c9 }

  condition:
    any of them
}