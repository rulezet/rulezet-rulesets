rule TTP_XOR_QUAD_CurrentVersionRun_79a0 {
  strings:
    $key_79a0 = { 2a cf [2] 0e c1 [2] 25 ed [2] 0b cf [2] 1f d4 [2] 10 ce [2] 0e d3 [2] 0c d2 [2] 17 d4 [2] 0b d3 [2] 17 fc }

  condition:
    any of them
}