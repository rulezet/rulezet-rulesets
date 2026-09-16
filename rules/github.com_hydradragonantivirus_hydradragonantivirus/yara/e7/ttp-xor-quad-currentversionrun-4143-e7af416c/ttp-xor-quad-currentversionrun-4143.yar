rule TTP_XOR_QUAD_CurrentVersionRun_4143 {
  strings:
    $key_4143 = { 12 2c [2] 36 22 [2] 1d 0e [2] 33 2c [2] 27 37 [2] 28 2d [2] 36 30 [2] 34 31 [2] 2f 37 [2] 33 30 [2] 2f 1f }

  condition:
    any of them
}