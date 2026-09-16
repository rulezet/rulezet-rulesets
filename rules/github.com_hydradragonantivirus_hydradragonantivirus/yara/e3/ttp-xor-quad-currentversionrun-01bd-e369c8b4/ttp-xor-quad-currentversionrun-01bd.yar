rule TTP_XOR_QUAD_CurrentVersionRun_01bd {
  strings:
    $key_01bd = { 52 d2 [2] 76 dc [2] 5d f0 [2] 73 d2 [2] 67 c9 [2] 68 d3 [2] 76 ce [2] 74 cf [2] 6f c9 [2] 73 ce [2] 6f e1 }

  condition:
    any of them
}