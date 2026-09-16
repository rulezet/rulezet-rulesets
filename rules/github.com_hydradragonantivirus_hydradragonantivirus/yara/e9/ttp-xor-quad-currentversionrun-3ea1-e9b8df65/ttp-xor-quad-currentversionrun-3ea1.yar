rule TTP_XOR_QUAD_CurrentVersionRun_3ea1 {
  strings:
    $key_3ea1 = { 6d ce [2] 49 c0 [2] 62 ec [2] 4c ce [2] 58 d5 [2] 57 cf [2] 49 d2 [2] 4b d3 [2] 50 d5 [2] 4c d2 [2] 50 fd }

  condition:
    any of them
}