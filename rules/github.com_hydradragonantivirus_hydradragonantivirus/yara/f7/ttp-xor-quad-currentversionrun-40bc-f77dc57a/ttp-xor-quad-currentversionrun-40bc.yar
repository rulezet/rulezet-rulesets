rule TTP_XOR_QUAD_CurrentVersionRun_40bc {
  strings:
    $key_40bc = { 13 d3 [2] 37 dd [2] 1c f1 [2] 32 d3 [2] 26 c8 [2] 29 d2 [2] 37 cf [2] 35 ce [2] 2e c8 [2] 32 cf [2] 2e e0 }

  condition:
    any of them
}