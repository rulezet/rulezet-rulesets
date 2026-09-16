rule TTP_XOR_QUAD_CurrentVersionRun_a4d4 {
  strings:
    $key_a4d4 = { f7 bb [2] d3 b5 [2] f8 99 [2] d6 bb [2] c2 a0 [2] cd ba [2] d3 a7 [2] d1 a6 [2] ca a0 [2] d6 a7 [2] ca 88 }

  condition:
    any of them
}