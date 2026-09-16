rule TTP_XOR_QUAD_CurrentVersionRun_1bbc {
  strings:
    $key_1bbc = { 48 d3 [2] 6c dd [2] 47 f1 [2] 69 d3 [2] 7d c8 [2] 72 d2 [2] 6c cf [2] 6e ce [2] 75 c8 [2] 69 cf [2] 75 e0 }

  condition:
    any of them
}