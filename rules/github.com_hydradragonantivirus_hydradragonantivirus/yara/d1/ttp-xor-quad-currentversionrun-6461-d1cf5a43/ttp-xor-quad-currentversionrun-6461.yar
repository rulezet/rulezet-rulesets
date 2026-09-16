rule TTP_XOR_QUAD_CurrentVersionRun_6461 {
  strings:
    $key_6461 = { 37 0e [2] 13 00 [2] 38 2c [2] 16 0e [2] 02 15 [2] 0d 0f [2] 13 12 [2] 11 13 [2] 0a 15 [2] 16 12 [2] 0a 3d }

  condition:
    any of them
}