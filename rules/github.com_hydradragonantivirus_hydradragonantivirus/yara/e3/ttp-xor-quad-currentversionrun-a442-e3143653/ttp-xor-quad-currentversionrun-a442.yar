rule TTP_XOR_QUAD_CurrentVersionRun_a442 {
  strings:
    $key_a442 = { f7 2d [2] d3 23 [2] f8 0f [2] d6 2d [2] c2 36 [2] cd 2c [2] d3 31 [2] d1 30 [2] ca 36 [2] d6 31 [2] ca 1e }

  condition:
    any of them
}