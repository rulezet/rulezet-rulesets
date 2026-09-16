rule TTP_XOR_QUAD_CurrentVersionRun_a4b0 {
  strings:
    $key_a4b0 = { f7 df [2] d3 d1 [2] f8 fd [2] d6 df [2] c2 c4 [2] cd de [2] d3 c3 [2] d1 c2 [2] ca c4 [2] d6 c3 [2] ca ec }

  condition:
    any of them
}