rule TTP_XOR_QUAD_CurrentVersionRun_b589 {
  strings:
    $key_b589 = { e6 e6 [2] c2 e8 [2] e9 c4 [2] c7 e6 [2] d3 fd [2] dc e7 [2] c2 fa [2] c0 fb [2] db fd [2] c7 fa [2] db d5 }

  condition:
    any of them
}