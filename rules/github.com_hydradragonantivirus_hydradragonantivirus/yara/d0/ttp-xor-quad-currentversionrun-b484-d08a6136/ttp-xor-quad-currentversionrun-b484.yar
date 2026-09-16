rule TTP_XOR_QUAD_CurrentVersionRun_b484 {
  strings:
    $key_b484 = { e7 eb [2] c3 e5 [2] e8 c9 [2] c6 eb [2] d2 f0 [2] dd ea [2] c3 f7 [2] c1 f6 [2] da f0 [2] c6 f7 [2] da d8 }

  condition:
    any of them
}