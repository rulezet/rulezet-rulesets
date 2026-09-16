rule TTP_XOR_QUAD_CurrentVersionRun_b1b0 {
  strings:
    $key_b1b0 = { e2 df [2] c6 d1 [2] ed fd [2] c3 df [2] d7 c4 [2] d8 de [2] c6 c3 [2] c4 c2 [2] df c4 [2] c3 c3 [2] df ec }

  condition:
    any of them
}