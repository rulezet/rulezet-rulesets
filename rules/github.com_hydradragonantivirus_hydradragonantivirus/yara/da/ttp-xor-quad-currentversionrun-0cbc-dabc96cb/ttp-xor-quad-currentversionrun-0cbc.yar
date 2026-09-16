rule TTP_XOR_QUAD_CurrentVersionRun_0cbc {
  strings:
    $key_0cbc = { 5f d3 [2] 7b dd [2] 50 f1 [2] 7e d3 [2] 6a c8 [2] 65 d2 [2] 7b cf [2] 79 ce [2] 62 c8 [2] 7e cf [2] 62 e0 }

  condition:
    any of them
}