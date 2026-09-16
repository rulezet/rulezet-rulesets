rule TTP_XOR_QUAD_CurrentVersionRun_c894 {
  strings:
    $key_c894 = { 9b fb [2] bf f5 [2] 94 d9 [2] ba fb [2] ae e0 [2] a1 fa [2] bf e7 [2] bd e6 [2] a6 e0 [2] ba e7 [2] a6 c8 }

  condition:
    any of them
}