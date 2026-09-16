rule TTP_XOR_QUAD_CurrentVersionRun_b2a7 {
  strings:
    $key_b2a7 = { e1 c8 [2] c5 c6 [2] ee ea [2] c0 c8 [2] d4 d3 [2] db c9 [2] c5 d4 [2] c7 d5 [2] dc d3 [2] c0 d4 [2] dc fb }

  condition:
    any of them
}