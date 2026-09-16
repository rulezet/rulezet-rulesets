rule TTP_XOR_QUAD_CurrentVersionRun_74a0 {
  strings:
    $key_74a0 = { 27 cf [2] 03 c1 [2] 28 ed [2] 06 cf [2] 12 d4 [2] 1d ce [2] 03 d3 [2] 01 d2 [2] 1a d4 [2] 06 d3 [2] 1a fc }

  condition:
    any of them
}