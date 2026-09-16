rule TTP_XOR_QUAD_CurrentVersionRun_a477 {
  strings:
    $key_a477 = { f7 18 [2] d3 16 [2] f8 3a [2] d6 18 [2] c2 03 [2] cd 19 [2] d3 04 [2] d1 05 [2] ca 03 [2] d6 04 [2] ca 2b }

  condition:
    any of them
}