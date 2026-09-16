rule TTP_XOR_QUAD_CurrentVersionRun_7fb0 {
  strings:
    $key_7fb0 = { 2c df [2] 08 d1 [2] 23 fd [2] 0d df [2] 19 c4 [2] 16 de [2] 08 c3 [2] 0a c2 [2] 11 c4 [2] 0d c3 [2] 11 ec }

  condition:
    any of them
}