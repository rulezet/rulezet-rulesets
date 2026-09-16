rule TTP_XOR_QUAD_CurrentVersionRun_2bbc {
  strings:
    $key_2bbc = { 78 d3 [2] 5c dd [2] 77 f1 [2] 59 d3 [2] 4d c8 [2] 42 d2 [2] 5c cf [2] 5e ce [2] 45 c8 [2] 59 cf [2] 45 e0 }

  condition:
    any of them
}