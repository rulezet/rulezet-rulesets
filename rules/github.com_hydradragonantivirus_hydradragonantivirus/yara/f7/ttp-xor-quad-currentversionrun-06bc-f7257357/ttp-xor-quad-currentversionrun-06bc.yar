rule TTP_XOR_QUAD_CurrentVersionRun_06bc {
  strings:
    $key_06bc = { 55 d3 [2] 71 dd [2] 5a f1 [2] 74 d3 [2] 60 c8 [2] 6f d2 [2] 71 cf [2] 73 ce [2] 68 c8 [2] 74 cf [2] 68 e0 }

  condition:
    any of them
}