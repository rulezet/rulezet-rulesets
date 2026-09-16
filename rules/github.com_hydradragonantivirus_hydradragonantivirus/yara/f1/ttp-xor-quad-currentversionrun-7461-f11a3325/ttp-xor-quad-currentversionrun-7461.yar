rule TTP_XOR_QUAD_CurrentVersionRun_7461 {
  strings:
    $key_7461 = { 27 0e [2] 03 00 [2] 28 2c [2] 06 0e [2] 12 15 [2] 1d 0f [2] 03 12 [2] 01 13 [2] 1a 15 [2] 06 12 [2] 1a 3d }

  condition:
    any of them
}