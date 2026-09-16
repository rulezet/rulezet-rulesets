rule TTP_XOR_QUAD_CurrentVersionRun_7ba0 {
  strings:
    $key_7ba0 = { 28 cf [2] 0c c1 [2] 27 ed [2] 09 cf [2] 1d d4 [2] 12 ce [2] 0c d3 [2] 0e d2 [2] 15 d4 [2] 09 d3 [2] 15 fc }

  condition:
    any of them
}