rule TTP_XOR_QUAD_CurrentVersionRun_f7bd {
  strings:
    $key_f7bd = { a4 d2 [2] 80 dc [2] ab f0 [2] 85 d2 [2] 91 c9 [2] 9e d3 [2] 80 ce [2] 82 cf [2] 99 c9 [2] 85 ce [2] 99 e1 }

  condition:
    any of them
}