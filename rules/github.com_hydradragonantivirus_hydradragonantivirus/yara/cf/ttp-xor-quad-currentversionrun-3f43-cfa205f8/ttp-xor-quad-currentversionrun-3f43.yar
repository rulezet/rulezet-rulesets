rule TTP_XOR_QUAD_CurrentVersionRun_3f43 {
  strings:
    $key_3f43 = { 6c 2c [2] 48 22 [2] 63 0e [2] 4d 2c [2] 59 37 [2] 56 2d [2] 48 30 [2] 4a 31 [2] 51 37 [2] 4d 30 [2] 51 1f }

  condition:
    any of them
}