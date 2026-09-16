rule TTP_XOR_QUAD_CurrentVersionRun_b285 {
  strings:
    $key_b285 = { e1 ea [2] c5 e4 [2] ee c8 [2] c0 ea [2] d4 f1 [2] db eb [2] c5 f6 [2] c7 f7 [2] dc f1 [2] c0 f6 [2] dc d9 }

  condition:
    any of them
}