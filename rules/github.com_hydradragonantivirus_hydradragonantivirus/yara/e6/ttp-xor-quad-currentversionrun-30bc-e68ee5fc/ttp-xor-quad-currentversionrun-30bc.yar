rule TTP_XOR_QUAD_CurrentVersionRun_30bc {
  strings:
    $key_30bc = { 63 d3 [2] 47 dd [2] 6c f1 [2] 42 d3 [2] 56 c8 [2] 59 d2 [2] 47 cf [2] 45 ce [2] 5e c8 [2] 42 cf [2] 5e e0 }

  condition:
    any of them
}