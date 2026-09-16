rule TTP_XOR_QUAD_CurrentVersionRun_0295 {
  strings:
    $key_0295 = { 51 fa [2] 75 f4 [2] 5e d8 [2] 70 fa [2] 64 e1 [2] 6b fb [2] 75 e6 [2] 77 e7 [2] 6c e1 [2] 70 e6 [2] 6c c9 }

  condition:
    any of them
}