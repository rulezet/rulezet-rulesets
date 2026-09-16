rule TTP_XOR_QUAD_CurrentVersionRun_6ba0 {
  strings:
    $key_6ba0 = { 38 cf [2] 1c c1 [2] 37 ed [2] 19 cf [2] 0d d4 [2] 02 ce [2] 1c d3 [2] 1e d2 [2] 05 d4 [2] 19 d3 [2] 05 fc }

  condition:
    any of them
}