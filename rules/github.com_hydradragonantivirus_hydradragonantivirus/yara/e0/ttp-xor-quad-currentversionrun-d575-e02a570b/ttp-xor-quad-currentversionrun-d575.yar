rule TTP_XOR_QUAD_CurrentVersionRun_d575 {
  strings:
    $key_d575 = { 86 1a [2] a2 14 [2] 89 38 [2] a7 1a [2] b3 01 [2] bc 1b [2] a2 06 [2] a0 07 [2] bb 01 [2] a7 06 [2] bb 29 }

  condition:
    any of them
}