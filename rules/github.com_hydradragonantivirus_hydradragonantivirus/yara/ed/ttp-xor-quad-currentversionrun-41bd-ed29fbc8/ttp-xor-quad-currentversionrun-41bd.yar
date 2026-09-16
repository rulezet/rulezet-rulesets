rule TTP_XOR_QUAD_CurrentVersionRun_41bd {
  strings:
    $key_41bd = { 12 d2 [2] 36 dc [2] 1d f0 [2] 33 d2 [2] 27 c9 [2] 28 d3 [2] 36 ce [2] 34 cf [2] 2f c9 [2] 33 ce [2] 2f e1 }

  condition:
    any of them
}