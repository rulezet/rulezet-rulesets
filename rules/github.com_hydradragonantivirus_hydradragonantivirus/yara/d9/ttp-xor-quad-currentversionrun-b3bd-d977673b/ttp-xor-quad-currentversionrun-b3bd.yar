rule TTP_XOR_QUAD_CurrentVersionRun_b3bd {
  strings:
    $key_b3bd = { e0 d2 [2] c4 dc [2] ef f0 [2] c1 d2 [2] d5 c9 [2] da d3 [2] c4 ce [2] c6 cf [2] dd c9 [2] c1 ce [2] dd e1 }

  condition:
    any of them
}