rule TTP_XOR_QUAD_CurrentVersionRun_6fb0 {
  strings:
    $key_6fb0 = { 3c df [2] 18 d1 [2] 33 fd [2] 1d df [2] 09 c4 [2] 06 de [2] 18 c3 [2] 1a c2 [2] 01 c4 [2] 1d c3 [2] 01 ec }

  condition:
    any of them
}