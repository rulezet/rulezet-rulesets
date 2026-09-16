rule TTP_XOR_QUAD_CurrentVersionRun_5681 {
  strings:
    $key_5681 = { 05 ee [2] 21 e0 [2] 0a cc [2] 24 ee [2] 30 f5 [2] 3f ef [2] 21 f2 [2] 23 f3 [2] 38 f5 [2] 24 f2 [2] 38 dd }

  condition:
    any of them
}