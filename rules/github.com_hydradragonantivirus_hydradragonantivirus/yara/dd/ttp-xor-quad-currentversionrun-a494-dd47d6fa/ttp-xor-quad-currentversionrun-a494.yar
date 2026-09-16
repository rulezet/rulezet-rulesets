rule TTP_XOR_QUAD_CurrentVersionRun_a494 {
  strings:
    $key_a494 = { f7 fb [2] d3 f5 [2] f8 d9 [2] d6 fb [2] c2 e0 [2] cd fa [2] d3 e7 [2] d1 e6 [2] ca e0 [2] d6 e7 [2] ca c8 }

  condition:
    any of them
}