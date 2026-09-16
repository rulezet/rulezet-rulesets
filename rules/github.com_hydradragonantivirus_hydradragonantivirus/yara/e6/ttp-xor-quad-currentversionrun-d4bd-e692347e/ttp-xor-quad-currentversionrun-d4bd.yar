rule TTP_XOR_QUAD_CurrentVersionRun_d4bd {
  strings:
    $key_d4bd = { 87 d2 [2] a3 dc [2] 88 f0 [2] a6 d2 [2] b2 c9 [2] bd d3 [2] a3 ce [2] a1 cf [2] ba c9 [2] a6 ce [2] ba e1 }

  condition:
    any of them
}