rule TTP_XOR_QUAD_CurrentVersionRun_0ea1 {
  strings:
    $key_0ea1 = { 5d ce [2] 79 c0 [2] 52 ec [2] 7c ce [2] 68 d5 [2] 67 cf [2] 79 d2 [2] 7b d3 [2] 60 d5 [2] 7c d2 [2] 60 fd }

  condition:
    any of them
}