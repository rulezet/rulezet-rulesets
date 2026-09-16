rule TTP_XOR_QUAD_CurrentVersionRun_6e43 {
  strings:
    $key_6e43 = { 3d 2c [2] 19 22 [2] 32 0e [2] 1c 2c [2] 08 37 [2] 07 2d [2] 19 30 [2] 1b 31 [2] 00 37 [2] 1c 30 [2] 00 1f }

  condition:
    any of them
}