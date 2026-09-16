rule TTP_XOR_QUAD_CurrentVersionRun_4da1 {
  strings:
    $key_4da1 = { 1e ce [2] 3a c0 [2] 11 ec [2] 3f ce [2] 2b d5 [2] 24 cf [2] 3a d2 [2] 38 d3 [2] 23 d5 [2] 3f d2 [2] 23 fd }

  condition:
    any of them
}