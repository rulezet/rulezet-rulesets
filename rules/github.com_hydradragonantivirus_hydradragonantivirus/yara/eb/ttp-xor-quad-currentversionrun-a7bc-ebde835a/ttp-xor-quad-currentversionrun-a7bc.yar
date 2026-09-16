rule TTP_XOR_QUAD_CurrentVersionRun_a7bc {
  strings:
    $key_a7bc = { f4 d3 [2] d0 dd [2] fb f1 [2] d5 d3 [2] c1 c8 [2] ce d2 [2] d0 cf [2] d2 ce [2] c9 c8 [2] d5 cf [2] c9 e0 }

  condition:
    any of them
}