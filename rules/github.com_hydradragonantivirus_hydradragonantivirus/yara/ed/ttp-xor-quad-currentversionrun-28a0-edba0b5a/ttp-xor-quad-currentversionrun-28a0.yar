rule TTP_XOR_QUAD_CurrentVersionRun_28a0 {
  strings:
    $key_28a0 = { 7b cf [2] 5f c1 [2] 74 ed [2] 5a cf [2] 4e d4 [2] 41 ce [2] 5f d3 [2] 5d d2 [2] 46 d4 [2] 5a d3 [2] 46 fc }

  condition:
    any of them
}