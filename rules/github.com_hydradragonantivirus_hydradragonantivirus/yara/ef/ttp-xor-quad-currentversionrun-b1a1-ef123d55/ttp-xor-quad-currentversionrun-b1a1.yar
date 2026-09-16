rule TTP_XOR_QUAD_CurrentVersionRun_b1a1 {
  strings:
    $key_b1a1 = { e2 ce [2] c6 c0 [2] ed ec [2] c3 ce [2] d7 d5 [2] d8 cf [2] c6 d2 [2] c4 d3 [2] df d5 [2] c3 d2 [2] df fd }

  condition:
    any of them
}