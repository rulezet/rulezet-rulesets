rule TTP_XOR_QUAD_CurrentVersionRun_a407 {
  strings:
    $key_a407 = { f7 68 [2] d3 66 [2] f8 4a [2] d6 68 [2] c2 73 [2] cd 69 [2] d3 74 [2] d1 75 [2] ca 73 [2] d6 74 [2] ca 5b }

  condition:
    any of them
}