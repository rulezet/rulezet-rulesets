rule TTP_XOR_QUAD_CurrentVersionRun_b375 {
  strings:
    $key_b375 = { e0 1a [2] c4 14 [2] ef 38 [2] c1 1a [2] d5 01 [2] da 1b [2] c4 06 [2] c6 07 [2] dd 01 [2] c1 06 [2] dd 29 }

  condition:
    any of them
}