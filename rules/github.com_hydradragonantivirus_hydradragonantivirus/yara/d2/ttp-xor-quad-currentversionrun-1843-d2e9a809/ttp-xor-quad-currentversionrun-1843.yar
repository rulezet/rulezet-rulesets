rule TTP_XOR_QUAD_CurrentVersionRun_1843 {
  strings:
    $key_1843 = { 4b 2c [2] 6f 22 [2] 44 0e [2] 6a 2c [2] 7e 37 [2] 71 2d [2] 6f 30 [2] 6d 31 [2] 76 37 [2] 6a 30 [2] 76 1f }

  condition:
    any of them
}