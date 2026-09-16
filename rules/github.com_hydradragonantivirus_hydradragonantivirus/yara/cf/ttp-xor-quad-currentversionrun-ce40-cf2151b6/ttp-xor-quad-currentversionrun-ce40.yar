rule TTP_XOR_QUAD_CurrentVersionRun_ce40 {
  strings:
    $key_ce40 = { 9d 2f [2] b9 21 [2] 92 0d [2] bc 2f [2] a8 34 [2] a7 2e [2] b9 33 [2] bb 32 [2] a0 34 [2] bc 33 [2] a0 1c }

  condition:
    any of them
}