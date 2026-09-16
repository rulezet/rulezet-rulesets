rule TTP_XOR_QUAD_CurrentVersionRun_d5eb {
  strings:
    $key_d5eb = { 86 84 [2] a2 8a [2] 89 a6 [2] a7 84 [2] b3 9f [2] bc 85 [2] a2 98 [2] a0 99 [2] bb 9f [2] a7 98 [2] bb b7 }

  condition:
    any of them
}