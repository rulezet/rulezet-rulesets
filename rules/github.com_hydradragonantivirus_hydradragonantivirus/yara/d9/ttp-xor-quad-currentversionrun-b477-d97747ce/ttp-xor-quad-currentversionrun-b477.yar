rule TTP_XOR_QUAD_CurrentVersionRun_b477 {
  strings:
    $key_b477 = { e7 18 [2] c3 16 [2] e8 3a [2] c6 18 [2] d2 03 [2] dd 19 [2] c3 04 [2] c1 05 [2] da 03 [2] c6 04 [2] da 2b }

  condition:
    any of them
}