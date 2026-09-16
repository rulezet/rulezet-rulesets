rule TTP_XOR_QUAD_CurrentVersionRun_d555 {
  strings:
    $key_d555 = { 86 3a [2] a2 34 [2] 89 18 [2] a7 3a [2] b3 21 [2] bc 3b [2] a2 26 [2] a0 27 [2] bb 21 [2] a7 26 [2] bb 09 }

  condition:
    any of them
}