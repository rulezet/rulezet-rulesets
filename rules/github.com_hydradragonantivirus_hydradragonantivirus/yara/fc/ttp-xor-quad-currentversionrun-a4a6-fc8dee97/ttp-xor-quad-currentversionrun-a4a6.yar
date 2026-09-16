rule TTP_XOR_QUAD_CurrentVersionRun_a4a6 {
  strings:
    $key_a4a6 = { f7 c9 [2] d3 c7 [2] f8 eb [2] d6 c9 [2] c2 d2 [2] cd c8 [2] d3 d5 [2] d1 d4 [2] ca d2 [2] d6 d5 [2] ca fa }

  condition:
    any of them
}