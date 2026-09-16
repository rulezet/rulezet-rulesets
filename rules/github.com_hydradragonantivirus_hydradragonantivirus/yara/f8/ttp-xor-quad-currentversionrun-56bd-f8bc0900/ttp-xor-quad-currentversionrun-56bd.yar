rule TTP_XOR_QUAD_CurrentVersionRun_56bd {
  strings:
    $key_56bd = { 05 d2 [2] 21 dc [2] 0a f0 [2] 24 d2 [2] 30 c9 [2] 3f d3 [2] 21 ce [2] 23 cf [2] 38 c9 [2] 24 ce [2] 38 e1 }

  condition:
    any of them
}