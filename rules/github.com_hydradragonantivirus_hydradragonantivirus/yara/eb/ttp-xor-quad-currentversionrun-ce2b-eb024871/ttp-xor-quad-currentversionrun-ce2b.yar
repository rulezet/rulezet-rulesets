rule TTP_XOR_QUAD_CurrentVersionRun_ce2b {
  strings:
    $key_ce2b = { 9d 44 [2] b9 4a [2] 92 66 [2] bc 44 [2] a8 5f [2] a7 45 [2] b9 58 [2] bb 59 [2] a0 5f [2] bc 58 [2] a0 77 }

  condition:
    any of them
}