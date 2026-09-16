rule TTP_XOR_QUAD_CurrentVersionRun_d247 {
  strings:
    $key_d247 = { 81 28 [2] a5 26 [2] 8e 0a [2] a0 28 [2] b4 33 [2] bb 29 [2] a5 34 [2] a7 35 [2] bc 33 [2] a0 34 [2] bc 1b }

  condition:
    any of them
}