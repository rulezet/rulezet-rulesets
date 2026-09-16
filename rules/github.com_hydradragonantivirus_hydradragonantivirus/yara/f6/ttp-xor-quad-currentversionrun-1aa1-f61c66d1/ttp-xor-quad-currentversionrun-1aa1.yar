rule TTP_XOR_QUAD_CurrentVersionRun_1aa1 {
  strings:
    $key_1aa1 = { 49 ce [2] 6d c0 [2] 46 ec [2] 68 ce [2] 7c d5 [2] 73 cf [2] 6d d2 [2] 6f d3 [2] 74 d5 [2] 68 d2 [2] 74 fd }

  condition:
    any of them
}