rule TTP_XOR_QUAD_CurrentVersionRun_a1a0 {
  strings:
    $key_a1a0 = { f2 cf [2] d6 c1 [2] fd ed [2] d3 cf [2] c7 d4 [2] c8 ce [2] d6 d3 [2] d4 d2 [2] cf d4 [2] d3 d3 [2] cf fc }

  condition:
    any of them
}