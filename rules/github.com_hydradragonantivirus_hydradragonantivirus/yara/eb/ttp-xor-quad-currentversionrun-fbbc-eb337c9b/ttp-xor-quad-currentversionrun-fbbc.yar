rule TTP_XOR_QUAD_CurrentVersionRun_fbbc {
  strings:
    $key_fbbc = { a8 d3 [2] 8c dd [2] a7 f1 [2] 89 d3 [2] 9d c8 [2] 92 d2 [2] 8c cf [2] 8e ce [2] 95 c8 [2] 89 cf [2] 95 e0 }

  condition:
    any of them
}