rule TTP_XOR_QUAD_CurrentVersionRun_d2a8 {
  strings:
    $key_d2a8 = { 81 c7 [2] a5 c9 [2] 8e e5 [2] a0 c7 [2] b4 dc [2] bb c6 [2] a5 db [2] a7 da [2] bc dc [2] a0 db [2] bc f4 }

  condition:
    any of them
}