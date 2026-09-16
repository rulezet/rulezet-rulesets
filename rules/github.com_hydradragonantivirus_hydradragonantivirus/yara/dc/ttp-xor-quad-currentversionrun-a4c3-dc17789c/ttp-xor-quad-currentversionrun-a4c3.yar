rule TTP_XOR_QUAD_CurrentVersionRun_a4c3 {
  strings:
    $key_a4c3 = { f7 ac [2] d3 a2 [2] f8 8e [2] d6 ac [2] c2 b7 [2] cd ad [2] d3 b0 [2] d1 b1 [2] ca b7 [2] d6 b0 [2] ca 9f }

  condition:
    any of them
}