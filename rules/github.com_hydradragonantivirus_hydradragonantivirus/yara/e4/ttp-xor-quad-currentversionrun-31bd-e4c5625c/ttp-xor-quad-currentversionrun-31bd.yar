rule TTP_XOR_QUAD_CurrentVersionRun_31bd {
  strings:
    $key_31bd = { 62 d2 [2] 46 dc [2] 6d f0 [2] 43 d2 [2] 57 c9 [2] 58 d3 [2] 46 ce [2] 44 cf [2] 5f c9 [2] 43 ce [2] 5f e1 }

  condition:
    any of them
}