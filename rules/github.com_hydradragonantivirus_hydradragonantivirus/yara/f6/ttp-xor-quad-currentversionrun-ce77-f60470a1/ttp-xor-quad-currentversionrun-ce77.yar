rule TTP_XOR_QUAD_CurrentVersionRun_ce77 {
  strings:
    $key_ce77 = { 9d 18 [2] b9 16 [2] 92 3a [2] bc 18 [2] a8 03 [2] a7 19 [2] b9 04 [2] bb 05 [2] a0 03 [2] bc 04 [2] a0 2b }

  condition:
    any of them
}