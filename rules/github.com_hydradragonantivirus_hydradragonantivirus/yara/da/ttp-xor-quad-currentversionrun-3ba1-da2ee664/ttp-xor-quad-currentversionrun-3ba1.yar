rule TTP_XOR_QUAD_CurrentVersionRun_3ba1 {
  strings:
    $key_3ba1 = { 68 ce [2] 4c c0 [2] 67 ec [2] 49 ce [2] 5d d5 [2] 52 cf [2] 4c d2 [2] 4e d3 [2] 55 d5 [2] 49 d2 [2] 55 fd }

  condition:
    any of them
}