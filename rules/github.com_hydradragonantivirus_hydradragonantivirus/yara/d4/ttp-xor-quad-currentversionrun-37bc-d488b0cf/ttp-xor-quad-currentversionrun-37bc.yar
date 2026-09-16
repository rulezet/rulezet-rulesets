rule TTP_XOR_QUAD_CurrentVersionRun_37bc {
  strings:
    $key_37bc = { 64 d3 [2] 40 dd [2] 6b f1 [2] 45 d3 [2] 51 c8 [2] 5e d2 [2] 40 cf [2] 42 ce [2] 59 c8 [2] 45 cf [2] 59 e0 }

  condition:
    any of them
}