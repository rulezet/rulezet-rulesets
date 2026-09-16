rule TTP_XOR_QUAD_CurrentVersionRun_b4da {
  strings:
    $key_b4da = { e7 b5 [2] c3 bb [2] e8 97 [2] c6 b5 [2] d2 ae [2] dd b4 [2] c3 a9 [2] c1 a8 [2] da ae [2] c6 a9 [2] da 86 }

  condition:
    any of them
}