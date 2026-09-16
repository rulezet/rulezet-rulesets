rule TTP_XOR_QUAD_CurrentVersionRun_a689 {
  strings:
    $key_a689 = { f5 e6 [2] d1 e8 [2] fa c4 [2] d4 e6 [2] c0 fd [2] cf e7 [2] d1 fa [2] d3 fb [2] c8 fd [2] d4 fa [2] c8 d5 }

  condition:
    any of them
}