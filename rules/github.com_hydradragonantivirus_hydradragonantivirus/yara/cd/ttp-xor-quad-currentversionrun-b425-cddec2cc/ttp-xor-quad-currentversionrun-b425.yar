rule TTP_XOR_QUAD_CurrentVersionRun_b425 {
  strings:
    $key_b425 = { e7 4a [2] c3 44 [2] e8 68 [2] c6 4a [2] d2 51 [2] dd 4b [2] c3 56 [2] c1 57 [2] da 51 [2] c6 56 [2] da 79 }

  condition:
    any of them
}