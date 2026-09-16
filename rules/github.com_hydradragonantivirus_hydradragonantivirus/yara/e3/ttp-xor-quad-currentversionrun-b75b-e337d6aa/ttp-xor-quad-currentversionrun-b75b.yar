rule TTP_XOR_QUAD_CurrentVersionRun_b75b {
  strings:
    $key_b75b = { e4 34 [2] c0 3a [2] eb 16 [2] c5 34 [2] d1 2f [2] de 35 [2] c0 28 [2] c2 29 [2] d9 2f [2] c5 28 [2] d9 07 }

  condition:
    any of them
}