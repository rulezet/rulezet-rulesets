rule TTP_XOR_QUAD_CurrentVersionRun_b794 {
  strings:
    $key_b794 = { e4 fb [2] c0 f5 [2] eb d9 [2] c5 fb [2] d1 e0 [2] de fa [2] c0 e7 [2] c2 e6 [2] d9 e0 [2] c5 e7 [2] d9 c8 }

  condition:
    any of them
}