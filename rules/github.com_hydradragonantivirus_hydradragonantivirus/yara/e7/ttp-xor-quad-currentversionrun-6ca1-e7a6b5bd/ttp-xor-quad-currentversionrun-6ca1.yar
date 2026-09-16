rule TTP_XOR_QUAD_CurrentVersionRun_6ca1 {
  strings:
    $key_6ca1 = { 3f ce [2] 1b c0 [2] 30 ec [2] 1e ce [2] 0a d5 [2] 05 cf [2] 1b d2 [2] 19 d3 [2] 02 d5 [2] 1e d2 [2] 02 fd }

  condition:
    any of them
}