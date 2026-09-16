rule TTP_XOR_QUAD_CurrentVersionRun_c4bd {
  strings:
    $key_c4bd = { 97 d2 [2] b3 dc [2] 98 f0 [2] b6 d2 [2] a2 c9 [2] ad d3 [2] b3 ce [2] b1 cf [2] aa c9 [2] b6 ce [2] aa e1 }

  condition:
    any of them
}