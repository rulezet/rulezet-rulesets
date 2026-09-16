rule TTP_XOR_QUAD_CurrentVersionRun_b469 {
  strings:
    $key_b469 = { e7 06 [2] c3 08 [2] e8 24 [2] c6 06 [2] d2 1d [2] dd 07 [2] c3 1a [2] c1 1b [2] da 1d [2] c6 1a [2] da 35 }

  condition:
    any of them
}