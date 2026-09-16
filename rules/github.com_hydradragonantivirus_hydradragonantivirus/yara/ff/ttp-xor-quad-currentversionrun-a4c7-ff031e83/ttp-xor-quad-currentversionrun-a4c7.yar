rule TTP_XOR_QUAD_CurrentVersionRun_a4c7 {
  strings:
    $key_a4c7 = { f7 a8 [2] d3 a6 [2] f8 8a [2] d6 a8 [2] c2 b3 [2] cd a9 [2] d3 b4 [2] d1 b5 [2] ca b3 [2] d6 b4 [2] ca 9b }

  condition:
    any of them
}