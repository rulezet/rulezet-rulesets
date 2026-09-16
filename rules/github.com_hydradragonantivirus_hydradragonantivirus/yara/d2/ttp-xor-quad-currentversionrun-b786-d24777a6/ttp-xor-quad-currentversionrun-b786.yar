rule TTP_XOR_QUAD_CurrentVersionRun_b786 {
  strings:
    $key_b786 = { e4 e9 [2] c0 e7 [2] eb cb [2] c5 e9 [2] d1 f2 [2] de e8 [2] c0 f5 [2] c2 f4 [2] d9 f2 [2] c5 f5 [2] d9 da }

  condition:
    any of them
}