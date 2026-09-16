rule TTP_XOR_QUAD_CurrentVersionRun_b47b {
  strings:
    $key_b47b = { e7 14 [2] c3 1a [2] e8 36 [2] c6 14 [2] d2 0f [2] dd 15 [2] c3 08 [2] c1 09 [2] da 0f [2] c6 08 [2] da 27 }

  condition:
    any of them
}