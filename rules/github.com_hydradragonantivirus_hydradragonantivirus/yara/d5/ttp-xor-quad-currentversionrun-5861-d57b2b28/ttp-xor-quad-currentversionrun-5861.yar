rule TTP_XOR_QUAD_CurrentVersionRun_5861 {
  strings:
    $key_5861 = { 0b 0e [2] 2f 00 [2] 04 2c [2] 2a 0e [2] 3e 15 [2] 31 0f [2] 2f 12 [2] 2d 13 [2] 36 15 [2] 2a 12 [2] 36 3d }

  condition:
    any of them
}