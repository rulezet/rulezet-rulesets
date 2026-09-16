rule TTP_XOR_QUAD_CurrentVersionRun_c0a1 {
  strings:
    $key_c0a1 = { 93 ce [2] b7 c0 [2] 9c ec [2] b2 ce [2] a6 d5 [2] a9 cf [2] b7 d2 [2] b5 d3 [2] ae d5 [2] b2 d2 [2] ae fd }

  condition:
    any of them
}