rule TTP_XOR_QUAD_CurrentVersionRun_20bd {
  strings:
    $key_20bd = { 73 d2 [2] 57 dc [2] 7c f0 [2] 52 d2 [2] 46 c9 [2] 49 d3 [2] 57 ce [2] 55 cf [2] 4e c9 [2] 52 ce [2] 4e e1 }

  condition:
    any of them
}