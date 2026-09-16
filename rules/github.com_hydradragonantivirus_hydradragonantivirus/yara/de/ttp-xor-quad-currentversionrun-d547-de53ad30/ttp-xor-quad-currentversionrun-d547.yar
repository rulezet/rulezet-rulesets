rule TTP_XOR_QUAD_CurrentVersionRun_d547 {
  strings:
    $key_d547 = { 86 28 [2] a2 26 [2] 89 0a [2] a7 28 [2] b3 33 [2] bc 29 [2] a2 34 [2] a0 35 [2] bb 33 [2] a7 34 [2] bb 1b }

  condition:
    any of them
}