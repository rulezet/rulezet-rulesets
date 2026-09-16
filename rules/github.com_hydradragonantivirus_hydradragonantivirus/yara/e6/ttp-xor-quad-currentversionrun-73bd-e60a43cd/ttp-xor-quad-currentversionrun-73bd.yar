rule TTP_XOR_QUAD_CurrentVersionRun_73bd {
  strings:
    $key_73bd = { 20 d2 [2] 04 dc [2] 2f f0 [2] 01 d2 [2] 15 c9 [2] 1a d3 [2] 04 ce [2] 06 cf [2] 1d c9 [2] 01 ce [2] 1d e1 }

  condition:
    any of them
}