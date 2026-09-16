rule TTP_XOR_QUAD_CurrentVersionRun_72bc {
  strings:
    $key_72bc = { 21 d3 [2] 05 dd [2] 2e f1 [2] 00 d3 [2] 14 c8 [2] 1b d2 [2] 05 cf [2] 07 ce [2] 1c c8 [2] 00 cf [2] 1c e0 }

  condition:
    any of them
}