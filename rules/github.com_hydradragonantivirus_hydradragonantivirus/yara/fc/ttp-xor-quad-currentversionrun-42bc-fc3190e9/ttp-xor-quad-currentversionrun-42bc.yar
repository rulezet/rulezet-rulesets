rule TTP_XOR_QUAD_CurrentVersionRun_42bc {
  strings:
    $key_42bc = { 11 d3 [2] 35 dd [2] 1e f1 [2] 30 d3 [2] 24 c8 [2] 2b d2 [2] 35 cf [2] 37 ce [2] 2c c8 [2] 30 cf [2] 2c e0 }

  condition:
    any of them
}