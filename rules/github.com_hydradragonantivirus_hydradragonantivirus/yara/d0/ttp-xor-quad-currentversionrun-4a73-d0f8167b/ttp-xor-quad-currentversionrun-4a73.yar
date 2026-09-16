rule TTP_XOR_QUAD_CurrentVersionRun_4a73 {
  strings:
    $key_4a73 = { 19 1c [2] 3d 12 [2] 16 3e [2] 38 1c [2] 2c 07 [2] 23 1d [2] 3d 00 [2] 3f 01 [2] 24 07 [2] 38 00 [2] 24 2f }

  condition:
    any of them
}