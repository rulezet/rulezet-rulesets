rule TTP_XOR_QUAD_CurrentVersionRun_0b43 {
  strings:
    $key_0b43 = { 58 2c [2] 7c 22 [2] 57 0e [2] 79 2c [2] 6d 37 [2] 62 2d [2] 7c 30 [2] 7e 31 [2] 65 37 [2] 79 30 [2] 65 1f }

  condition:
    any of them
}