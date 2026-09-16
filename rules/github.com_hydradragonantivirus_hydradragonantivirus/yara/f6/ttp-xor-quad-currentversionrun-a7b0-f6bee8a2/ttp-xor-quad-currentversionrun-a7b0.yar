rule TTP_XOR_QUAD_CurrentVersionRun_a7b0 {
  strings:
    $key_a7b0 = { f4 df [2] d0 d1 [2] fb fd [2] d5 df [2] c1 c4 [2] ce de [2] d0 c3 [2] d2 c2 [2] c9 c4 [2] d5 c3 [2] c9 ec }

  condition:
    any of them
}