rule TTP_XOR_QUAD_CurrentVersionRun_04b0 {
  strings:
    $key_04b0 = { 57 df [2] 73 d1 [2] 58 fd [2] 76 df [2] 62 c4 [2] 6d de [2] 73 c3 [2] 71 c2 [2] 6a c4 [2] 76 c3 [2] 6a ec }

  condition:
    any of them
}