rule TTP_XOR_QUAD_CurrentVersionRun_d545 {
  strings:
    $key_d545 = { 86 2a [2] a2 24 [2] 89 08 [2] a7 2a [2] b3 31 [2] bc 2b [2] a2 36 [2] a0 37 [2] bb 31 [2] a7 36 [2] bb 19 }

  condition:
    any of them
}