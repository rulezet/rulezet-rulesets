rule TTP_XOR_QUAD_CurrentVersionRun_1f43 {
  strings:
    $key_1f43 = { 4c 2c [2] 68 22 [2] 43 0e [2] 6d 2c [2] 79 37 [2] 76 2d [2] 68 30 [2] 6a 31 [2] 71 37 [2] 6d 30 [2] 71 1f }

  condition:
    any of them
}