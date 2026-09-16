rule TTP_XOR_QUAD_CurrentVersionRun_04bd {
  strings:
    $key_04bd = { 57 d2 [2] 73 dc [2] 58 f0 [2] 76 d2 [2] 62 c9 [2] 6d d3 [2] 73 ce [2] 71 cf [2] 6a c9 [2] 76 ce [2] 6a e1 }

  condition:
    any of them
}