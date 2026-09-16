rule TTP_XOR_QUAD_CurrentVersionRun_c1a1 {
  strings:
    $key_c1a1 = { 92 ce [2] b6 c0 [2] 9d ec [2] b3 ce [2] a7 d5 [2] a8 cf [2] b6 d2 [2] b4 d3 [2] af d5 [2] b3 d2 [2] af fd }

  condition:
    any of them
}