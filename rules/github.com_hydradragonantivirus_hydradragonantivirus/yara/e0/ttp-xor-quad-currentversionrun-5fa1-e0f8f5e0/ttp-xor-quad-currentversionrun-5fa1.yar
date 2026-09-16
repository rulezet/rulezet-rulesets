rule TTP_XOR_QUAD_CurrentVersionRun_5fa1 {
  strings:
    $key_5fa1 = { 0c ce [2] 28 c0 [2] 03 ec [2] 2d ce [2] 39 d5 [2] 36 cf [2] 28 d2 [2] 2a d3 [2] 31 d5 [2] 2d d2 [2] 31 fd }

  condition:
    any of them
}