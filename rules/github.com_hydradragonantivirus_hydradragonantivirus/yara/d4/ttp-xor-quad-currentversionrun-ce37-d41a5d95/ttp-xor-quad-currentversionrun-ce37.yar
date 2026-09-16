rule TTP_XOR_QUAD_CurrentVersionRun_ce37 {
  strings:
    $key_ce37 = { 9d 58 [2] b9 56 [2] 92 7a [2] bc 58 [2] a8 43 [2] a7 59 [2] b9 44 [2] bb 45 [2] a0 43 [2] bc 44 [2] a0 6b }

  condition:
    any of them
}