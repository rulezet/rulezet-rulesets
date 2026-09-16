rule TTP_XOR_QUAD_CurrentVersionRun_ce45 {
  strings:
    $key_ce45 = { 9d 2a [2] b9 24 [2] 92 08 [2] bc 2a [2] a8 31 [2] a7 2b [2] b9 36 [2] bb 37 [2] a0 31 [2] bc 36 [2] a0 19 }

  condition:
    any of them
}