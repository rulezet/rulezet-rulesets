rule TTP_XOR_QUAD_CurrentVersionRun_5373 {
  strings:
    $key_5373 = { 00 1c [2] 24 12 [2] 0f 3e [2] 21 1c [2] 35 07 [2] 3a 1d [2] 24 00 [2] 26 01 [2] 3d 07 [2] 21 00 [2] 3d 2f }

  condition:
    any of them
}