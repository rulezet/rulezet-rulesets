rule TTP_XOR_QUAD_CurrentVersionRun_f0bc {
  strings:
    $key_f0bc = { a3 d3 [2] 87 dd [2] ac f1 [2] 82 d3 [2] 96 c8 [2] 99 d2 [2] 87 cf [2] 85 ce [2] 9e c8 [2] 82 cf [2] 9e e0 }

  condition:
    any of them
}