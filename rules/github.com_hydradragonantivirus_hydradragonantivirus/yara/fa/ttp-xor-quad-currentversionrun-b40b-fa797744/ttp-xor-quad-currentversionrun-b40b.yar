rule TTP_XOR_QUAD_CurrentVersionRun_b40b {
  strings:
    $key_b40b = { e7 64 [2] c3 6a [2] e8 46 [2] c6 64 [2] d2 7f [2] dd 65 [2] c3 78 [2] c1 79 [2] da 7f [2] c6 78 [2] da 57 }

  condition:
    any of them
}