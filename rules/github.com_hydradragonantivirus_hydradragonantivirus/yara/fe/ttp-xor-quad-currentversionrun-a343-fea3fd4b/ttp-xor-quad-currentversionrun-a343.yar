rule TTP_XOR_QUAD_CurrentVersionRun_a343 {
  strings:
    $key_a343 = { f0 2c [2] d4 22 [2] ff 0e [2] d1 2c [2] c5 37 [2] ca 2d [2] d4 30 [2] d6 31 [2] cd 37 [2] d1 30 [2] cd 1f }

  condition:
    any of them
}