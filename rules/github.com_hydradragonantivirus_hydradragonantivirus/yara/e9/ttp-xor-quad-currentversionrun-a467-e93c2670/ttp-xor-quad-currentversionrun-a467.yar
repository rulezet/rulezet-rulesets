rule TTP_XOR_QUAD_CurrentVersionRun_a467 {
  strings:
    $key_a467 = { f7 08 [2] d3 06 [2] f8 2a [2] d6 08 [2] c2 13 [2] cd 09 [2] d3 14 [2] d1 15 [2] ca 13 [2] d6 14 [2] ca 3b }

  condition:
    any of them
}