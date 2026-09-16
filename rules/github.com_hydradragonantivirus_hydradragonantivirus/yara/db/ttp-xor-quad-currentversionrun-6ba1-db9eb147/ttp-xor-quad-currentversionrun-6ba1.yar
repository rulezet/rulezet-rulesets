rule TTP_XOR_QUAD_CurrentVersionRun_6ba1 {
  strings:
    $key_6ba1 = { 38 ce [2] 1c c0 [2] 37 ec [2] 19 ce [2] 0d d5 [2] 02 cf [2] 1c d2 [2] 1e d3 [2] 05 d5 [2] 19 d2 [2] 05 fd }

  condition:
    any of them
}