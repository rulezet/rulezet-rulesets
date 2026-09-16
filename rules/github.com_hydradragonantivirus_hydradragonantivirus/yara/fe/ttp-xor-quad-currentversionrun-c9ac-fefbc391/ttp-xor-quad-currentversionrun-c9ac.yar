rule TTP_XOR_QUAD_CurrentVersionRun_c9ac {
  strings:
    $key_c9ac = { 9a c3 [2] be cd [2] 95 e1 [2] bb c3 [2] af d8 [2] a0 c2 [2] be df [2] bc de [2] a7 d8 [2] bb df [2] a7 f0 }

  condition:
    any of them
}