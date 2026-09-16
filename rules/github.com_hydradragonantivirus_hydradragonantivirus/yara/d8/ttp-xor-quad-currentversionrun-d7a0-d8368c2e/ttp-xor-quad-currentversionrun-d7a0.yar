rule TTP_XOR_QUAD_CurrentVersionRun_d7a0 {
  strings:
    $key_d7a0 = { 84 cf [2] a0 c1 [2] 8b ed [2] a5 cf [2] b1 d4 [2] be ce [2] a0 d3 [2] a2 d2 [2] b9 d4 [2] a5 d3 [2] b9 fc }

  condition:
    any of them
}