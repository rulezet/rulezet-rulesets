rule TTP_XOR_QUAD_CurrentVersionRun_bab6 {
  strings:
    $key_bab6 = { e9 d9 [2] cd d7 [2] e6 fb [2] c8 d9 [2] dc c2 [2] d3 d8 [2] cd c5 [2] cf c4 [2] d4 c2 [2] c8 c5 [2] d4 ea }

  condition:
    any of them
}