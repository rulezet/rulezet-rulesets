rule TTP_XOR_QUAD_CurrentVersionRun_ce75 {
  strings:
    $key_ce75 = { 9d 1a [2] b9 14 [2] 92 38 [2] bc 1a [2] a8 01 [2] a7 1b [2] b9 06 [2] bb 07 [2] a0 01 [2] bc 06 [2] a0 29 }

  condition:
    any of them
}