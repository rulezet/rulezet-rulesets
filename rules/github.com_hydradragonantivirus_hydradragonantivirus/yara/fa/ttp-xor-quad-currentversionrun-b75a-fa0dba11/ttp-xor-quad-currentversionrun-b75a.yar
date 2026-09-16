rule TTP_XOR_QUAD_CurrentVersionRun_b75a {
  strings:
    $key_b75a = { e4 35 [2] c0 3b [2] eb 17 [2] c5 35 [2] d1 2e [2] de 34 [2] c0 29 [2] c2 28 [2] d9 2e [2] c5 29 [2] d9 06 }

  condition:
    any of them
}