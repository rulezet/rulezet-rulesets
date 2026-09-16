rule TTP_XOR_QUAD_CurrentVersionRun_fca1 {
  strings:
    $key_fca1 = { af ce [2] 8b c0 [2] a0 ec [2] 8e ce [2] 9a d5 [2] 95 cf [2] 8b d2 [2] 89 d3 [2] 92 d5 [2] 8e d2 [2] 92 fd }

  condition:
    any of them
}