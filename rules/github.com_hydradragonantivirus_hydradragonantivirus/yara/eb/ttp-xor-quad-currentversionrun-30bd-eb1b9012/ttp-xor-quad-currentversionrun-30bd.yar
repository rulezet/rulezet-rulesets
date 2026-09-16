rule TTP_XOR_QUAD_CurrentVersionRun_30bd {
  strings:
    $key_30bd = { 63 d2 [2] 47 dc [2] 6c f0 [2] 42 d2 [2] 56 c9 [2] 59 d3 [2] 47 ce [2] 45 cf [2] 5e c9 [2] 42 ce [2] 5e e1 }

  condition:
    any of them
}