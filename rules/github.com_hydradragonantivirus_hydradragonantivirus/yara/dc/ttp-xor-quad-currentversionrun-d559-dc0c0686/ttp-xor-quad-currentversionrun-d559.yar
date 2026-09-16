rule TTP_XOR_QUAD_CurrentVersionRun_d559 {
  strings:
    $key_d559 = { 86 36 [2] a2 38 [2] 89 14 [2] a7 36 [2] b3 2d [2] bc 37 [2] a2 2a [2] a0 2b [2] bb 2d [2] a7 2a [2] bb 05 }

  condition:
    any of them
}