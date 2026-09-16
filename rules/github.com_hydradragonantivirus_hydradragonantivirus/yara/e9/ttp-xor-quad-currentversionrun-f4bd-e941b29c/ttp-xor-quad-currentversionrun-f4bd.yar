rule TTP_XOR_QUAD_CurrentVersionRun_f4bd {
  strings:
    $key_f4bd = { a7 d2 [2] 83 dc [2] a8 f0 [2] 86 d2 [2] 92 c9 [2] 9d d3 [2] 83 ce [2] 81 cf [2] 9a c9 [2] 86 ce [2] 9a e1 }

  condition:
    any of them
}