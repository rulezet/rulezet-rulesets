rule TTP_XOR_QUAD_CurrentVersionRun_d537 {
  strings:
    $key_d537 = { 86 58 [2] a2 56 [2] 89 7a [2] a7 58 [2] b3 43 [2] bc 59 [2] a2 44 [2] a0 45 [2] bb 43 [2] a7 44 [2] bb 6b }

  condition:
    any of them
}