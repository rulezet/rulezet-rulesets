rule TTP_XOR_QUAD_CurrentVersionRun_00bc {
  strings:
    $key_00bc = { 53 d3 [2] 77 dd [2] 5c f1 [2] 72 d3 [2] 66 c8 [2] 69 d2 [2] 77 cf [2] 75 ce [2] 6e c8 [2] 72 cf [2] 6e e0 }

  condition:
    any of them
}