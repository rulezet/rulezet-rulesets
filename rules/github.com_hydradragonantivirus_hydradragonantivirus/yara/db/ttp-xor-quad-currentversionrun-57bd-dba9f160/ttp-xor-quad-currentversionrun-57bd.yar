rule TTP_XOR_QUAD_CurrentVersionRun_57bd {
  strings:
    $key_57bd = { 04 d2 [2] 20 dc [2] 0b f0 [2] 25 d2 [2] 31 c9 [2] 3e d3 [2] 20 ce [2] 22 cf [2] 39 c9 [2] 25 ce [2] 39 e1 }

  condition:
    any of them
}