rule TTP_XOR_QUAD_CurrentVersionRun_27bd {
  strings:
    $key_27bd = { 74 d2 [2] 50 dc [2] 7b f0 [2] 55 d2 [2] 41 c9 [2] 4e d3 [2] 50 ce [2] 52 cf [2] 49 c9 [2] 55 ce [2] 49 e1 }

  condition:
    any of them
}