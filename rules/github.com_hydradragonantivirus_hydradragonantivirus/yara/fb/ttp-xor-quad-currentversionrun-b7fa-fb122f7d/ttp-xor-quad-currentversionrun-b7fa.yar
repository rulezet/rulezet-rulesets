rule TTP_XOR_QUAD_CurrentVersionRun_b7fa {
  strings:
    $key_b7fa = { e4 95 [2] c0 9b [2] eb b7 [2] c5 95 [2] d1 8e [2] de 94 [2] c0 89 [2] c2 88 [2] d9 8e [2] c5 89 [2] d9 a6 }

  condition:
    any of them
}