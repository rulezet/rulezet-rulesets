rule TTP_XOR_QUAD_CurrentVersionRun_78a0 {
  strings:
    $key_78a0 = { 2b cf [2] 0f c1 [2] 24 ed [2] 0a cf [2] 1e d4 [2] 11 ce [2] 0f d3 [2] 0d d2 [2] 16 d4 [2] 0a d3 [2] 16 fc }

  condition:
    any of them
}