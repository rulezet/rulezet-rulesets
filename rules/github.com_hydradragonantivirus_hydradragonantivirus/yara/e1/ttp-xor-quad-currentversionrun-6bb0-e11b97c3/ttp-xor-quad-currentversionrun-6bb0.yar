rule TTP_XOR_QUAD_CurrentVersionRun_6bb0 {
  strings:
    $key_6bb0 = { 38 df [2] 1c d1 [2] 37 fd [2] 19 df [2] 0d c4 [2] 02 de [2] 1c c3 [2] 1e c2 [2] 05 c4 [2] 19 c3 [2] 05 ec }

  condition:
    any of them
}