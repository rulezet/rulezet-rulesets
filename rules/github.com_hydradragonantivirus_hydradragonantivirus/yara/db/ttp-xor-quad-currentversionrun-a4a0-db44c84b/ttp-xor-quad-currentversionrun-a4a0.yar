rule TTP_XOR_QUAD_CurrentVersionRun_a4a0 {
  strings:
    $key_a4a0 = { f7 cf [2] d3 c1 [2] f8 ed [2] d6 cf [2] c2 d4 [2] cd ce [2] d3 d3 [2] d1 d2 [2] ca d4 [2] d6 d3 [2] ca fc }

  condition:
    any of them
}