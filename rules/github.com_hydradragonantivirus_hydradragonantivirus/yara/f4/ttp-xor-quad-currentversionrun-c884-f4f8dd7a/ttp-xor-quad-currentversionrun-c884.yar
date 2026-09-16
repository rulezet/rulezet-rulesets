rule TTP_XOR_QUAD_CurrentVersionRun_c884 {
  strings:
    $key_c884 = { 9b eb [2] bf e5 [2] 94 c9 [2] ba eb [2] ae f0 [2] a1 ea [2] bf f7 [2] bd f6 [2] a6 f0 [2] ba f7 [2] a6 d8 }

  condition:
    any of them
}