rule TTP_XOR_QUAD_CurrentVersionRun_cf84 {
  strings:
    $key_cf84 = { 9c eb [2] b8 e5 [2] 93 c9 [2] bd eb [2] a9 f0 [2] a6 ea [2] b8 f7 [2] ba f6 [2] a1 f0 [2] bd f7 [2] a1 d8 }

  condition:
    any of them
}