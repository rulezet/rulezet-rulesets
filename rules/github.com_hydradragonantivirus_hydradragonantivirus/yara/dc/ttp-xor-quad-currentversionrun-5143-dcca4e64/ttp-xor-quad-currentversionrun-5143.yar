rule TTP_XOR_QUAD_CurrentVersionRun_5143 {
  strings:
    $key_5143 = { 02 2c [2] 26 22 [2] 0d 0e [2] 23 2c [2] 37 37 [2] 38 2d [2] 26 30 [2] 24 31 [2] 3f 37 [2] 23 30 [2] 3f 1f }

  condition:
    any of them
}