rule TTP_XOR_QUAD_CurrentVersionRun_d385 {
  strings:
    $key_d385 = { 80 ea [2] a4 e4 [2] 8f c8 [2] a1 ea [2] b5 f1 [2] ba eb [2] a4 f6 [2] a6 f7 [2] bd f1 [2] a1 f6 [2] bd d9 }

  condition:
    any of them
}