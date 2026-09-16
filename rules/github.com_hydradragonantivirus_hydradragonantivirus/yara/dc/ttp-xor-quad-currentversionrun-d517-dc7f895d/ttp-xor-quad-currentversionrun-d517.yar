rule TTP_XOR_QUAD_CurrentVersionRun_d517 {
  strings:
    $key_d517 = { 86 78 [2] a2 76 [2] 89 5a [2] a7 78 [2] b3 63 [2] bc 79 [2] a2 64 [2] a0 65 [2] bb 63 [2] a7 64 [2] bb 4b }

  condition:
    any of them
}