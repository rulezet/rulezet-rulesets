rule TTP_XOR_QUAD_CurrentVersionRun_b497 {
  strings:
    $key_b497 = { e7 f8 [2] c3 f6 [2] e8 da [2] c6 f8 [2] d2 e3 [2] dd f9 [2] c3 e4 [2] c1 e5 [2] da e3 [2] c6 e4 [2] da cb }

  condition:
    any of them
}