rule TTP_XOR_QUAD_CurrentVersionRun_bab7 {
  strings:
    $key_bab7 = { e9 d8 [2] cd d6 [2] e6 fa [2] c8 d8 [2] dc c3 [2] d3 d9 [2] cd c4 [2] cf c5 [2] d4 c3 [2] c8 c4 [2] d4 eb }

  condition:
    any of them
}