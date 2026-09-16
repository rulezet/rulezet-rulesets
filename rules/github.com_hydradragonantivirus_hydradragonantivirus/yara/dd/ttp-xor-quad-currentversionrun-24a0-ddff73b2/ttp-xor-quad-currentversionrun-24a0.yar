rule TTP_XOR_QUAD_CurrentVersionRun_24a0 {
  strings:
    $key_24a0 = { 77 cf [2] 53 c1 [2] 78 ed [2] 56 cf [2] 42 d4 [2] 4d ce [2] 53 d3 [2] 51 d2 [2] 4a d4 [2] 56 d3 [2] 4a fc }

  condition:
    any of them
}