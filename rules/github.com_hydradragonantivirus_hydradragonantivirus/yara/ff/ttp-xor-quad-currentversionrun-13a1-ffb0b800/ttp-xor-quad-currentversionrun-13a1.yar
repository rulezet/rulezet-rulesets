rule TTP_XOR_QUAD_CurrentVersionRun_13a1 {
  strings:
    $key_13a1 = { 40 ce [2] 64 c0 [2] 4f ec [2] 61 ce [2] 75 d5 [2] 7a cf [2] 64 d2 [2] 66 d3 [2] 7d d5 [2] 61 d2 [2] 7d fd }

  condition:
    any of them
}