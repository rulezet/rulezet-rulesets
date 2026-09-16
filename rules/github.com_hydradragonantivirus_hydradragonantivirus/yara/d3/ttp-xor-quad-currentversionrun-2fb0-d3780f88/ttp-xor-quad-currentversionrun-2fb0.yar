rule TTP_XOR_QUAD_CurrentVersionRun_2fb0 {
  strings:
    $key_2fb0 = { 7c df [2] 58 d1 [2] 73 fd [2] 5d df [2] 49 c4 [2] 46 de [2] 58 c3 [2] 5a c2 [2] 41 c4 [2] 5d c3 [2] 41 ec }

  condition:
    any of them
}