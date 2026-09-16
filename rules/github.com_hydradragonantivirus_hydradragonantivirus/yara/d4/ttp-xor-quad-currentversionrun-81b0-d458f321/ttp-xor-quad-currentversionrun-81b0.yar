rule TTP_XOR_QUAD_CurrentVersionRun_81b0 {
  strings:
    $key_81b0 = { d2 df [2] f6 d1 [2] dd fd [2] f3 df [2] e7 c4 [2] e8 de [2] f6 c3 [2] f4 c2 [2] ef c4 [2] f3 c3 [2] ef ec }

  condition:
    any of them
}