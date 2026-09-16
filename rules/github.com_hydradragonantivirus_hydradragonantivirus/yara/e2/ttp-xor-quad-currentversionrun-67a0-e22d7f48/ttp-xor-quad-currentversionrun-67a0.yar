rule TTP_XOR_QUAD_CurrentVersionRun_67a0 {
  strings:
    $key_67a0 = { 34 cf [2] 10 c1 [2] 3b ed [2] 15 cf [2] 01 d4 [2] 0e ce [2] 10 d3 [2] 12 d2 [2] 09 d4 [2] 15 d3 [2] 09 fc }

  condition:
    any of them
}