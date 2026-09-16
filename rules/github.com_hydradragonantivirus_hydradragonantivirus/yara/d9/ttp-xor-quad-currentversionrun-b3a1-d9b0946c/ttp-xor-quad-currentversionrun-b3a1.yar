rule TTP_XOR_QUAD_CurrentVersionRun_b3a1 {
  strings:
    $key_b3a1 = { e0 ce [2] c4 c0 [2] ef ec [2] c1 ce [2] d5 d5 [2] da cf [2] c4 d2 [2] c6 d3 [2] dd d5 [2] c1 d2 [2] dd fd }

  condition:
    any of them
}