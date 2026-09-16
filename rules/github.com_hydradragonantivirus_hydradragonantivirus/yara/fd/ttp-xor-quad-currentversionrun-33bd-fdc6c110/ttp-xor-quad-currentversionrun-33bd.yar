rule TTP_XOR_QUAD_CurrentVersionRun_33bd {
  strings:
    $key_33bd = { 60 d2 [2] 44 dc [2] 6f f0 [2] 41 d2 [2] 55 c9 [2] 5a d3 [2] 44 ce [2] 46 cf [2] 5d c9 [2] 41 ce [2] 5d e1 }

  condition:
    any of them
}