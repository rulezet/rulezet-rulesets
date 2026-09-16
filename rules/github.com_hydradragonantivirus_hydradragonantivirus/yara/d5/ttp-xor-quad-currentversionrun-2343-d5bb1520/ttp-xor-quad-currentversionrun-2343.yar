rule TTP_XOR_QUAD_CurrentVersionRun_2343 {
  strings:
    $key_2343 = { 70 2c [2] 54 22 [2] 7f 0e [2] 51 2c [2] 45 37 [2] 4a 2d [2] 54 30 [2] 56 31 [2] 4d 37 [2] 51 30 [2] 4d 1f }

  condition:
    any of them
}