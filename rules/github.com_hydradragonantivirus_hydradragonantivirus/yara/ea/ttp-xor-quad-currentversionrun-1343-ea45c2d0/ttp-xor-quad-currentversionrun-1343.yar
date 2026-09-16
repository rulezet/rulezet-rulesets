rule TTP_XOR_QUAD_CurrentVersionRun_1343 {
  strings:
    $key_1343 = { 40 2c [2] 64 22 [2] 4f 0e [2] 61 2c [2] 75 37 [2] 7a 2d [2] 64 30 [2] 66 31 [2] 7d 37 [2] 61 30 [2] 7d 1f }

  condition:
    any of them
}