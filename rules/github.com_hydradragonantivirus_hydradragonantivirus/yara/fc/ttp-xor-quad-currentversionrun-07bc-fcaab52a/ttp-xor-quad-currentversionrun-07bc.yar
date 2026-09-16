rule TTP_XOR_QUAD_CurrentVersionRun_07bc {
  strings:
    $key_07bc = { 54 d3 [2] 70 dd [2] 5b f1 [2] 75 d3 [2] 61 c8 [2] 6e d2 [2] 70 cf [2] 72 ce [2] 69 c8 [2] 75 cf [2] 69 e0 }

  condition:
    any of them
}