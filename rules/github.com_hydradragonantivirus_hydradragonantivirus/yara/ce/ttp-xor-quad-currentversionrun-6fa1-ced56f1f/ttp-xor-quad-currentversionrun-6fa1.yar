rule TTP_XOR_QUAD_CurrentVersionRun_6fa1 {
  strings:
    $key_6fa1 = { 3c ce [2] 18 c0 [2] 33 ec [2] 1d ce [2] 09 d5 [2] 06 cf [2] 18 d2 [2] 1a d3 [2] 01 d5 [2] 1d d2 [2] 01 fd }

  condition:
    any of them
}