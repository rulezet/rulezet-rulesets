rule TTP_XOR_QUAD_CurrentVersionRun_b2b5 {
  strings:
    $key_b2b5 = { e1 da [2] c5 d4 [2] ee f8 [2] c0 da [2] d4 c1 [2] db db [2] c5 c6 [2] c7 c7 [2] dc c1 [2] c0 c6 [2] dc e9 }

  condition:
    any of them
}