rule TTP_XOR_QUAD_CurrentVersionRun_22bc {
  strings:
    $key_22bc = { 71 d3 [2] 55 dd [2] 7e f1 [2] 50 d3 [2] 44 c8 [2] 4b d2 [2] 55 cf [2] 57 ce [2] 4c c8 [2] 50 cf [2] 4c e0 }

  condition:
    any of them
}