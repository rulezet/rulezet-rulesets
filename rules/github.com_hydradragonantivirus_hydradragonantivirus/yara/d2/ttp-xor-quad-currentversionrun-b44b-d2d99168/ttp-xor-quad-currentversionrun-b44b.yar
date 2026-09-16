rule TTP_XOR_QUAD_CurrentVersionRun_b44b {
  strings:
    $key_b44b = { e7 24 [2] c3 2a [2] e8 06 [2] c6 24 [2] d2 3f [2] dd 25 [2] c3 38 [2] c1 39 [2] da 3f [2] c6 38 [2] da 17 }

  condition:
    any of them
}