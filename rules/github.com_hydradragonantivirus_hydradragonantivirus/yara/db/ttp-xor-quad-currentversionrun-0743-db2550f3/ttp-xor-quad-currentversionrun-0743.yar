rule TTP_XOR_QUAD_CurrentVersionRun_0743 {
  strings:
    $key_0743 = { 54 2c [2] 70 22 [2] 5b 0e [2] 75 2c [2] 61 37 [2] 6e 2d [2] 70 30 [2] 72 31 [2] 69 37 [2] 75 30 [2] 69 1f }

  condition:
    any of them
}