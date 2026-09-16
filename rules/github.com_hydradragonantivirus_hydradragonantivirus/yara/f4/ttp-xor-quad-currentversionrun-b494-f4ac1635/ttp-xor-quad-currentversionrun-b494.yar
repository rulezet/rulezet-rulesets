rule TTP_XOR_QUAD_CurrentVersionRun_b494 {
  strings:
    $key_b494 = { e7 fb [2] c3 f5 [2] e8 d9 [2] c6 fb [2] d2 e0 [2] dd fa [2] c3 e7 [2] c1 e6 [2] da e0 [2] c6 e7 [2] da c8 }

  condition:
    any of them
}