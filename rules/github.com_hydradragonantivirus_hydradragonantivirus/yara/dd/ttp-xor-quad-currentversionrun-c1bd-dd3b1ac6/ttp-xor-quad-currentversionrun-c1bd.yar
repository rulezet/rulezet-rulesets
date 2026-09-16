rule TTP_XOR_QUAD_CurrentVersionRun_c1bd {
  strings:
    $key_c1bd = { 92 d2 [2] b6 dc [2] 9d f0 [2] b3 d2 [2] a7 c9 [2] a8 d3 [2] b6 ce [2] b4 cf [2] af c9 [2] b3 ce [2] af e1 }

  condition:
    any of them
}