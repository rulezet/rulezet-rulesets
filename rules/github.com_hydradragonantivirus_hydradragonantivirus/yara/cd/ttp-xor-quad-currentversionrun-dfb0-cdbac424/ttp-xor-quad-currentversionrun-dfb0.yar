rule TTP_XOR_QUAD_CurrentVersionRun_dfb0 {
  strings:
    $key_dfb0 = { 8c df [2] a8 d1 [2] 83 fd [2] ad df [2] b9 c4 [2] b6 de [2] a8 c3 [2] aa c2 [2] b1 c4 [2] ad c3 [2] b1 ec }

  condition:
    any of them
}