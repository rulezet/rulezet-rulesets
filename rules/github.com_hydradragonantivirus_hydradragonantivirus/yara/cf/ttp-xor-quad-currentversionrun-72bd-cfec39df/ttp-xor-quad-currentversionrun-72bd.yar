rule TTP_XOR_QUAD_CurrentVersionRun_72bd {
  strings:
    $key_72bd = { 21 d2 [2] 05 dc [2] 2e f0 [2] 00 d2 [2] 14 c9 [2] 1b d3 [2] 05 ce [2] 07 cf [2] 1c c9 [2] 00 ce [2] 1c e1 }

  condition:
    any of them
}