rule TTP_XOR_QUAD_CurrentVersionRun_b6a0 {
  strings:
    $key_b6a0 = { e5 cf [2] c1 c1 [2] ea ed [2] c4 cf [2] d0 d4 [2] df ce [2] c1 d3 [2] c3 d2 [2] d8 d4 [2] c4 d3 [2] d8 fc }

  condition:
    any of them
}