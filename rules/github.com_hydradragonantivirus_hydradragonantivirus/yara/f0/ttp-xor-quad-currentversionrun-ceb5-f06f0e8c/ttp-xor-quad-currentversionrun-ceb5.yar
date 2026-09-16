rule TTP_XOR_QUAD_CurrentVersionRun_ceb5 {
  strings:
    $key_ceb5 = { 9d da [2] b9 d4 [2] 92 f8 [2] bc da [2] a8 c1 [2] a7 db [2] b9 c6 [2] bb c7 [2] a0 c1 [2] bc c6 [2] a0 e9 }

  condition:
    any of them
}