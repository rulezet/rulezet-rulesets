rule TTP_XOR_QUAD_CurrentVersionRun_b4e6 {
  strings:
    $key_b4e6 = { e7 89 [2] c3 87 [2] e8 ab [2] c6 89 [2] d2 92 [2] dd 88 [2] c3 95 [2] c1 94 [2] da 92 [2] c6 95 [2] da ba }

  condition:
    any of them
}