rule TTP_XOR_QUAD_CurrentVersionRun_6161 {
  strings:
    $key_6161 = { 32 0e [2] 16 00 [2] 3d 2c [2] 13 0e [2] 07 15 [2] 08 0f [2] 16 12 [2] 14 13 [2] 0f 15 [2] 13 12 [2] 0f 3d }

  condition:
    any of them
}