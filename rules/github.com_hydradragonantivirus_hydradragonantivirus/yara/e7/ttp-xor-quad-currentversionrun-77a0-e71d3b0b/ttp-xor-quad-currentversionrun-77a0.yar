rule TTP_XOR_QUAD_CurrentVersionRun_77a0 {
  strings:
    $key_77a0 = { 24 cf [2] 00 c1 [2] 2b ed [2] 05 cf [2] 11 d4 [2] 1e ce [2] 00 d3 [2] 02 d2 [2] 19 d4 [2] 05 d3 [2] 19 fc }

  condition:
    any of them
}