rule TTP_XOR_QUAD_CurrentVersionRun_17bd {
  strings:
    $key_17bd = { 44 d2 [2] 60 dc [2] 4b f0 [2] 65 d2 [2] 71 c9 [2] 7e d3 [2] 60 ce [2] 62 cf [2] 79 c9 [2] 65 ce [2] 79 e1 }

  condition:
    any of them
}