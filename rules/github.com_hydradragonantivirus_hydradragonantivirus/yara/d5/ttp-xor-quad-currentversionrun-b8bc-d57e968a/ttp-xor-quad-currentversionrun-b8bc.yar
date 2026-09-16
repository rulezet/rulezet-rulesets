rule TTP_XOR_QUAD_CurrentVersionRun_b8bc {
  strings:
    $key_b8bc = { eb d3 [2] cf dd [2] e4 f1 [2] ca d3 [2] de c8 [2] d1 d2 [2] cf cf [2] cd ce [2] d6 c8 [2] ca cf [2] d6 e0 }

  condition:
    any of them
}