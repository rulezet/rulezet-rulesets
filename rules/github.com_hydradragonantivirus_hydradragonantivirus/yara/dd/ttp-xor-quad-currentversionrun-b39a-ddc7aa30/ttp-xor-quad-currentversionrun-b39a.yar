rule TTP_XOR_QUAD_CurrentVersionRun_b39a {
  strings:
    $key_b39a = { e0 f5 [2] c4 fb [2] ef d7 [2] c1 f5 [2] d5 ee [2] da f4 [2] c4 e9 [2] c6 e8 [2] dd ee [2] c1 e9 [2] dd c6 }

  condition:
    any of them
}