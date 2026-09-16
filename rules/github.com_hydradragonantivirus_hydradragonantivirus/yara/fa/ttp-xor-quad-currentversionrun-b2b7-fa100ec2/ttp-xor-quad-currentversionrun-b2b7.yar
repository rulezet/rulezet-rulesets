rule TTP_XOR_QUAD_CurrentVersionRun_b2b7 {
  strings:
    $key_b2b7 = { e1 d8 [2] c5 d6 [2] ee fa [2] c0 d8 [2] d4 c3 [2] db d9 [2] c5 c4 [2] c7 c5 [2] dc c3 [2] c0 c4 [2] dc eb }

  condition:
    any of them
}