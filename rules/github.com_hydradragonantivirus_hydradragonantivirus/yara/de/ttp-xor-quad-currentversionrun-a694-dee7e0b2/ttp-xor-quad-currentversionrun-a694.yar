rule TTP_XOR_QUAD_CurrentVersionRun_a694 {
  strings:
    $key_a694 = { f5 fb [2] d1 f5 [2] fa d9 [2] d4 fb [2] c0 e0 [2] cf fa [2] d1 e7 [2] d3 e6 [2] c8 e0 [2] d4 e7 [2] c8 c8 }

  condition:
    any of them
}