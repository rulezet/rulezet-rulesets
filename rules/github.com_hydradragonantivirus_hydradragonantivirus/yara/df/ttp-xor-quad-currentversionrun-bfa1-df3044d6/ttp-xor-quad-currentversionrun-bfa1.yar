rule TTP_XOR_QUAD_CurrentVersionRun_bfa1 {
  strings:
    $key_bfa1 = { ec ce [2] c8 c0 [2] e3 ec [2] cd ce [2] d9 d5 [2] d6 cf [2] c8 d2 [2] ca d3 [2] d1 d5 [2] cd d2 [2] d1 fd }

  condition:
    any of them
}