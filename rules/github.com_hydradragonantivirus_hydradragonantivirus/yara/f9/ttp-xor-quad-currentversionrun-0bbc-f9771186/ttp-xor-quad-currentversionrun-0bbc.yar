rule TTP_XOR_QUAD_CurrentVersionRun_0bbc {
  strings:
    $key_0bbc = { 58 d3 [2] 7c dd [2] 57 f1 [2] 79 d3 [2] 6d c8 [2] 62 d2 [2] 7c cf [2] 7e ce [2] 65 c8 [2] 79 cf [2] 65 e0 }

  condition:
    any of them
}