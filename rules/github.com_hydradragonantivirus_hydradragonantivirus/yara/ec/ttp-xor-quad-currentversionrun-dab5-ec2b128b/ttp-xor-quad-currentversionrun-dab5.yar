rule TTP_XOR_QUAD_CurrentVersionRun_dab5 {
  strings:
    $key_dab5 = { 89 da [2] ad d4 [2] 86 f8 [2] a8 da [2] bc c1 [2] b3 db [2] ad c6 [2] af c7 [2] b4 c1 [2] a8 c6 [2] b4 e9 }

  condition:
    any of them
}