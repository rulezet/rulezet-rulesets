rule TTP_XOR_QUAD_CurrentVersionRun_b5b0 {
  strings:
    $key_b5b0 = { e6 df [2] c2 d1 [2] e9 fd [2] c7 df [2] d3 c4 [2] dc de [2] c2 c3 [2] c0 c2 [2] db c4 [2] c7 c3 [2] db ec }

  condition:
    any of them
}