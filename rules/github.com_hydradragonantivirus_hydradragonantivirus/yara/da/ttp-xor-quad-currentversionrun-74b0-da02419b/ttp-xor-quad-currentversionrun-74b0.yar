rule TTP_XOR_QUAD_CurrentVersionRun_74b0 {
  strings:
    $key_74b0 = { 27 df [2] 03 d1 [2] 28 fd [2] 06 df [2] 12 c4 [2] 1d de [2] 03 c3 [2] 01 c2 [2] 1a c4 [2] 06 c3 [2] 1a ec }

  condition:
    any of them
}