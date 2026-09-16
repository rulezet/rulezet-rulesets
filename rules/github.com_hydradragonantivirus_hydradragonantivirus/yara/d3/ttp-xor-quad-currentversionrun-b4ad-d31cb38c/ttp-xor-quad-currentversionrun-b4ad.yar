rule TTP_XOR_QUAD_CurrentVersionRun_b4ad {
  strings:
    $key_b4ad = { e7 c2 [2] c3 cc [2] e8 e0 [2] c6 c2 [2] d2 d9 [2] dd c3 [2] c3 de [2] c1 df [2] da d9 [2] c6 de [2] da f1 }

  condition:
    any of them
}