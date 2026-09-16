rule TTP_XOR_QUAD_CurrentVersionRun_b424 {
  strings:
    $key_b424 = { e7 4b [2] c3 45 [2] e8 69 [2] c6 4b [2] d2 50 [2] dd 4a [2] c3 57 [2] c1 56 [2] da 50 [2] c6 57 [2] da 78 }

  condition:
    any of them
}