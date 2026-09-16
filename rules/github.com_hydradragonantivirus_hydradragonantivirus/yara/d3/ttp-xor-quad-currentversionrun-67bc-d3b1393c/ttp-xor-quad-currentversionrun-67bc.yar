rule TTP_XOR_QUAD_CurrentVersionRun_67bc {
  strings:
    $key_67bc = { 34 d3 [2] 10 dd [2] 3b f1 [2] 15 d3 [2] 01 c8 [2] 0e d2 [2] 10 cf [2] 12 ce [2] 09 c8 [2] 15 cf [2] 09 e0 }

  condition:
    any of them
}