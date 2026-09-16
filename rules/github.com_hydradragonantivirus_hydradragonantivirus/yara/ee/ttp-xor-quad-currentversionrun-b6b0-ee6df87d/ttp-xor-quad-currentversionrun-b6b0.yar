rule TTP_XOR_QUAD_CurrentVersionRun_b6b0 {
  strings:
    $key_b6b0 = { e5 df [2] c1 d1 [2] ea fd [2] c4 df [2] d0 c4 [2] df de [2] c1 c3 [2] c3 c2 [2] d8 c4 [2] c4 c3 [2] d8 ec }

  condition:
    any of them
}