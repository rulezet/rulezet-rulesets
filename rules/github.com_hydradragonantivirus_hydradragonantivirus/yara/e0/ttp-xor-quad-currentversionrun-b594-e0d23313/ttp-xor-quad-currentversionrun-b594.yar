rule TTP_XOR_QUAD_CurrentVersionRun_b594 {
  strings:
    $key_b594 = { e6 fb [2] c2 f5 [2] e9 d9 [2] c7 fb [2] d3 e0 [2] dc fa [2] c2 e7 [2] c0 e6 [2] db e0 [2] c7 e7 [2] db c8 }

  condition:
    any of them
}