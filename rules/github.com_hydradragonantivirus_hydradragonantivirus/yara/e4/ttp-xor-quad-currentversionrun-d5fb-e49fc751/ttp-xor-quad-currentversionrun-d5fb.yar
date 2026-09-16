rule TTP_XOR_QUAD_CurrentVersionRun_d5fb {
  strings:
    $key_d5fb = { 86 94 [2] a2 9a [2] 89 b6 [2] a7 94 [2] b3 8f [2] bc 95 [2] a2 88 [2] a0 89 [2] bb 8f [2] a7 88 [2] bb a7 }

  condition:
    any of them
}