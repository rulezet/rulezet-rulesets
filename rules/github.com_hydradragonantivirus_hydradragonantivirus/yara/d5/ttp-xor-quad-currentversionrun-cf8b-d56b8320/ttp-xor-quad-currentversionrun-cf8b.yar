rule TTP_XOR_QUAD_CurrentVersionRun_cf8b {
  strings:
    $key_cf8b = { 9c e4 [2] b8 ea [2] 93 c6 [2] bd e4 [2] a9 ff [2] a6 e5 [2] b8 f8 [2] ba f9 [2] a1 ff [2] bd f8 [2] a1 d7 }

  condition:
    any of them
}