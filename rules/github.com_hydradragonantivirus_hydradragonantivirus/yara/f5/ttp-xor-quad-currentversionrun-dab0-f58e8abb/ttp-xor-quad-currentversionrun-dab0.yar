rule TTP_XOR_QUAD_CurrentVersionRun_dab0 {
  strings:
    $key_dab0 = { 89 df [2] ad d1 [2] 86 fd [2] a8 df [2] bc c4 [2] b3 de [2] ad c3 [2] af c2 [2] b4 c4 [2] a8 c3 [2] b4 ec }

  condition:
    any of them
}