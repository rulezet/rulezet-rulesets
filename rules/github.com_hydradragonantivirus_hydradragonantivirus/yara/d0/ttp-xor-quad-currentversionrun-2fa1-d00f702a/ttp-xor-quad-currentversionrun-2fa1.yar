rule TTP_XOR_QUAD_CurrentVersionRun_2fa1 {
  strings:
    $key_2fa1 = { 7c ce [2] 58 c0 [2] 73 ec [2] 5d ce [2] 49 d5 [2] 46 cf [2] 58 d2 [2] 5a d3 [2] 41 d5 [2] 5d d2 [2] 41 fd }

  condition:
    any of them
}