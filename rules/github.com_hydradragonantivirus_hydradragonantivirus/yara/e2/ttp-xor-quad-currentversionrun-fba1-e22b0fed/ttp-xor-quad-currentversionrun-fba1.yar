rule TTP_XOR_QUAD_CurrentVersionRun_fba1 {
  strings:
    $key_fba1 = { a8 ce [2] 8c c0 [2] a7 ec [2] 89 ce [2] 9d d5 [2] 92 cf [2] 8c d2 [2] 8e d3 [2] 95 d5 [2] 89 d2 [2] 95 fd }

  condition:
    any of them
}