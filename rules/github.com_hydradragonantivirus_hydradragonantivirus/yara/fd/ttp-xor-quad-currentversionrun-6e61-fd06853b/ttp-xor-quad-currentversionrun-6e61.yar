rule TTP_XOR_QUAD_CurrentVersionRun_6e61 {
  strings:
    $key_6e61 = { 3d 0e [2] 19 00 [2] 32 2c [2] 1c 0e [2] 08 15 [2] 07 0f [2] 19 12 [2] 1b 13 [2] 00 15 [2] 1c 12 [2] 00 3d }

  condition:
    any of them
}