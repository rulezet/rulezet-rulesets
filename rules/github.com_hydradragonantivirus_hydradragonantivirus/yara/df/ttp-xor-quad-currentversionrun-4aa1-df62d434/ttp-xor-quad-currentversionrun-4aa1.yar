rule TTP_XOR_QUAD_CurrentVersionRun_4aa1 {
  strings:
    $key_4aa1 = { 19 ce [2] 3d c0 [2] 16 ec [2] 38 ce [2] 2c d5 [2] 23 cf [2] 3d d2 [2] 3f d3 [2] 24 d5 [2] 38 d2 [2] 24 fd }

  condition:
    any of them
}