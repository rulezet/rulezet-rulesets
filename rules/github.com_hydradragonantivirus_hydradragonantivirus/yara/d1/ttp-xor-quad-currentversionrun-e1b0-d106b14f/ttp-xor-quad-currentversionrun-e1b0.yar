rule TTP_XOR_QUAD_CurrentVersionRun_e1b0 {
  strings:
    $key_e1b0 = { b2 df [2] 96 d1 [2] bd fd [2] 93 df [2] 87 c4 [2] 88 de [2] 96 c3 [2] 94 c2 [2] 8f c4 [2] 93 c3 [2] 8f ec }

  condition:
    any of them
}