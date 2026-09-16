rule TTP_XOR_QUAD_CurrentVersionRun_44b0 {
  strings:
    $key_44b0 = { 17 df [2] 33 d1 [2] 18 fd [2] 36 df [2] 22 c4 [2] 2d de [2] 33 c3 [2] 31 c2 [2] 2a c4 [2] 36 c3 [2] 2a ec }

  condition:
    any of them
}