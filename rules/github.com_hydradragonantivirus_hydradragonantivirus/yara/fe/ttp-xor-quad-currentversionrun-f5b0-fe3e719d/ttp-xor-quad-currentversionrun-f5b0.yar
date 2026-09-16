rule TTP_XOR_QUAD_CurrentVersionRun_f5b0 {
  strings:
    $key_f5b0 = { a6 df [2] 82 d1 [2] a9 fd [2] 87 df [2] 93 c4 [2] 9c de [2] 82 c3 [2] 80 c2 [2] 9b c4 [2] 87 c3 [2] 9b ec }

  condition:
    any of them
}