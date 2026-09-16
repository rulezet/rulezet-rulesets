rule TTP_XOR_QUAD_CurrentVersionRun_d558 {
  strings:
    $key_d558 = { 86 37 [2] a2 39 [2] 89 15 [2] a7 37 [2] b3 2c [2] bc 36 [2] a2 2b [2] a0 2a [2] bb 2c [2] a7 2b [2] bb 04 }

  condition:
    any of them
}