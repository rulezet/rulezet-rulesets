rule TTP_XOR_QUAD_CurrentVersionRun_a463 {
  strings:
    $key_a463 = { f7 0c [2] d3 02 [2] f8 2e [2] d6 0c [2] c2 17 [2] cd 0d [2] d3 10 [2] d1 11 [2] ca 17 [2] d6 10 [2] ca 3f }

  condition:
    any of them
}