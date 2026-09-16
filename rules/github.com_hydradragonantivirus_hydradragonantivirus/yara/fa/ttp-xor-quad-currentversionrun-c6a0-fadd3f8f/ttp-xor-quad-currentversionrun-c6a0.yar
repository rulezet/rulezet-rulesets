rule TTP_XOR_QUAD_CurrentVersionRun_c6a0 {
  strings:
    $key_c6a0 = { 95 cf [2] b1 c1 [2] 9a ed [2] b4 cf [2] a0 d4 [2] af ce [2] b1 d3 [2] b3 d2 [2] a8 d4 [2] b4 d3 [2] a8 fc }

  condition:
    any of them
}