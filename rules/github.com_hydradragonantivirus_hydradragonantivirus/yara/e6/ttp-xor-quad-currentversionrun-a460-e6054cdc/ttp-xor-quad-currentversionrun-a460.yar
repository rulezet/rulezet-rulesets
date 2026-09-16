rule TTP_XOR_QUAD_CurrentVersionRun_a460 {
  strings:
    $key_a460 = { f7 0f [2] d3 01 [2] f8 2d [2] d6 0f [2] c2 14 [2] cd 0e [2] d3 13 [2] d1 12 [2] ca 14 [2] d6 13 [2] ca 3c }

  condition:
    any of them
}