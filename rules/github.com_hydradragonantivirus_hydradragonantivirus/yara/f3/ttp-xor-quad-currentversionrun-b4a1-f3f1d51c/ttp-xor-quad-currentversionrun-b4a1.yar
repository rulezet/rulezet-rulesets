rule TTP_XOR_QUAD_CurrentVersionRun_b4a1 {
  strings:
    $key_b4a1 = { e7 ce [2] c3 c0 [2] e8 ec [2] c6 ce [2] d2 d5 [2] dd cf [2] c3 d2 [2] c1 d3 [2] da d5 [2] c6 d2 [2] da fd }

  condition:
    any of them
}