rule TTP_XOR_QUAD_CurrentVersionRun_16bd {
  strings:
    $key_16bd = { 45 d2 [2] 61 dc [2] 4a f0 [2] 64 d2 [2] 70 c9 [2] 7f d3 [2] 61 ce [2] 63 cf [2] 78 c9 [2] 64 ce [2] 78 e1 }

  condition:
    any of them
}