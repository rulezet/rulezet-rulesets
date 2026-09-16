rule TTP_XOR_QUAD_CurrentVersionRun_ce63 {
  strings:
    $key_ce63 = { 9d 0c [2] b9 02 [2] 92 2e [2] bc 0c [2] a8 17 [2] a7 0d [2] b9 10 [2] bb 11 [2] a0 17 [2] bc 10 [2] a0 3f }

  condition:
    any of them
}