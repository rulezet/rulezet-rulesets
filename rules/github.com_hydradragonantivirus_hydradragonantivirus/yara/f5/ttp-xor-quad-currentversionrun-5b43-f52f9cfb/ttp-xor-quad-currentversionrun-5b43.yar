rule TTP_XOR_QUAD_CurrentVersionRun_5b43 {
  strings:
    $key_5b43 = { 08 2c [2] 2c 22 [2] 07 0e [2] 29 2c [2] 3d 37 [2] 32 2d [2] 2c 30 [2] 2e 31 [2] 35 37 [2] 29 30 [2] 35 1f }

  condition:
    any of them
}