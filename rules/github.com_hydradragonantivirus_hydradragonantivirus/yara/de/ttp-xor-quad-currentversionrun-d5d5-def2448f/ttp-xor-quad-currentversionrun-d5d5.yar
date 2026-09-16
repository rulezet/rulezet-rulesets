rule TTP_XOR_QUAD_CurrentVersionRun_d5d5 {
  strings:
    $key_d5d5 = { 86 ba [2] a2 b4 [2] 89 98 [2] a7 ba [2] b3 a1 [2] bc bb [2] a2 a6 [2] a0 a7 [2] bb a1 [2] a7 a6 [2] bb 89 }

  condition:
    any of them
}