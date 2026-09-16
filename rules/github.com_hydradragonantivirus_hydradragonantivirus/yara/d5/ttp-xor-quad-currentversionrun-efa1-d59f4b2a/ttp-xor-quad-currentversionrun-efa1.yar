rule TTP_XOR_QUAD_CurrentVersionRun_efa1 {
  strings:
    $key_efa1 = { bc ce [2] 98 c0 [2] b3 ec [2] 9d ce [2] 89 d5 [2] 86 cf [2] 98 d2 [2] 9a d3 [2] 81 d5 [2] 9d d2 [2] 81 fd }

  condition:
    any of them
}