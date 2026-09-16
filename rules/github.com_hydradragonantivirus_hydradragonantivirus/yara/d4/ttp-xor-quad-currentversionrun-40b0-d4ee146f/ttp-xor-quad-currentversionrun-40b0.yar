rule TTP_XOR_QUAD_CurrentVersionRun_40b0 {
  strings:
    $key_40b0 = { 13 df [2] 37 d1 [2] 1c fd [2] 32 df [2] 26 c4 [2] 29 de [2] 37 c3 [2] 35 c2 [2] 2e c4 [2] 32 c3 [2] 2e ec }

  condition:
    any of them
}