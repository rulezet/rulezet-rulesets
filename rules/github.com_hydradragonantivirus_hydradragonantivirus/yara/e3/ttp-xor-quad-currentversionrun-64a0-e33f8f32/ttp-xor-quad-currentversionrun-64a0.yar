rule TTP_XOR_QUAD_CurrentVersionRun_64a0 {
  strings:
    $key_64a0 = { 37 cf [2] 13 c1 [2] 38 ed [2] 16 cf [2] 02 d4 [2] 0d ce [2] 13 d3 [2] 11 d2 [2] 0a d4 [2] 16 d3 [2] 0a fc }

  condition:
    any of them
}