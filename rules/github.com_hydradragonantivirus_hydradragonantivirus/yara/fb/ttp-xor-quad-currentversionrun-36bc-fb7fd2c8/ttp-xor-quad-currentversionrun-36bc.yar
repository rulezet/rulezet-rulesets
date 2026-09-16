rule TTP_XOR_QUAD_CurrentVersionRun_36bc {
  strings:
    $key_36bc = { 65 d3 [2] 41 dd [2] 6a f1 [2] 44 d3 [2] 50 c8 [2] 5f d2 [2] 41 cf [2] 43 ce [2] 58 c8 [2] 44 cf [2] 58 e0 }

  condition:
    any of them
}