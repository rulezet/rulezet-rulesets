rule TTP_XOR_QUAD_CurrentVersionRun_1c43 {
  strings:
    $key_1c43 = { 4f 2c [2] 6b 22 [2] 40 0e [2] 6e 2c [2] 7a 37 [2] 75 2d [2] 6b 30 [2] 69 31 [2] 72 37 [2] 6e 30 [2] 72 1f }

  condition:
    any of them
}