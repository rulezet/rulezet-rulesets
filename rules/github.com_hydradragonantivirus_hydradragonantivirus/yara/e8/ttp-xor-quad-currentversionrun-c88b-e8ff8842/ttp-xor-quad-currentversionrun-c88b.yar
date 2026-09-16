rule TTP_XOR_QUAD_CurrentVersionRun_c88b {
  strings:
    $key_c88b = { 9b e4 [2] bf ea [2] 94 c6 [2] ba e4 [2] ae ff [2] a1 e5 [2] bf f8 [2] bd f9 [2] a6 ff [2] ba f8 [2] a6 d7 }

  condition:
    any of them
}