rule TTP_XOR_QUAD_CurrentVersionRun_ce73 {
  strings:
    $key_ce73 = { 9d 1c [2] b9 12 [2] 92 3e [2] bc 1c [2] a8 07 [2] a7 1d [2] b9 00 [2] bb 01 [2] a0 07 [2] bc 00 [2] a0 2f }

  condition:
    any of them
}