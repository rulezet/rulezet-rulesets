rule TTP_XOR_QUAD_CurrentVersionRun_b7bc {
  strings:
    $key_b7bc = { e4 d3 [2] c0 dd [2] eb f1 [2] c5 d3 [2] d1 c8 [2] de d2 [2] c0 cf [2] c2 ce [2] d9 c8 [2] c5 cf [2] d9 e0 }

  condition:
    any of them
}