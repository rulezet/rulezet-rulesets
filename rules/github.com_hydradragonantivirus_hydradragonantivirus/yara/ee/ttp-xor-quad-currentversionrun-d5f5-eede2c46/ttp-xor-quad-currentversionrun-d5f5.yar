rule TTP_XOR_QUAD_CurrentVersionRun_d5f5 {
  strings:
    $key_d5f5 = { 86 9a [2] a2 94 [2] 89 b8 [2] a7 9a [2] b3 81 [2] bc 9b [2] a2 86 [2] a0 87 [2] bb 81 [2] a7 86 [2] bb a9 }

  condition:
    any of them
}