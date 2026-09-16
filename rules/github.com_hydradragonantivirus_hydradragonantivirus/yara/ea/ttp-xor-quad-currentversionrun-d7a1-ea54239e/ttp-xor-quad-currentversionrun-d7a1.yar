rule TTP_XOR_QUAD_CurrentVersionRun_d7a1 {
  strings:
    $key_d7a1 = { 84 ce [2] a0 c0 [2] 8b ec [2] a5 ce [2] b1 d5 [2] be cf [2] a0 d2 [2] a2 d3 [2] b9 d5 [2] a5 d2 [2] b9 fd }

  condition:
    any of them
}