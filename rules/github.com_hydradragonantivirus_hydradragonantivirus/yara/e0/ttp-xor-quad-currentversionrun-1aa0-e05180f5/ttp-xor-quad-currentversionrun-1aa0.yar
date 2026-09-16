rule TTP_XOR_QUAD_CurrentVersionRun_1aa0 {
  strings:
    $key_1aa0 = { 49 cf [2] 6d c1 [2] 46 ed [2] 68 cf [2] 7c d4 [2] 73 ce [2] 6d d3 [2] 6f d2 [2] 74 d4 [2] 68 d3 [2] 74 fc }

  condition:
    any of them
}