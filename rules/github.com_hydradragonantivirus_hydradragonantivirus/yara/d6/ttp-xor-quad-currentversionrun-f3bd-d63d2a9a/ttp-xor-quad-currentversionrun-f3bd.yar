rule TTP_XOR_QUAD_CurrentVersionRun_f3bd {
  strings:
    $key_f3bd = { a0 d2 [2] 84 dc [2] af f0 [2] 81 d2 [2] 95 c9 [2] 9a d3 [2] 84 ce [2] 86 cf [2] 9d c9 [2] 81 ce [2] 9d e1 }

  condition:
    any of them
}