rule TTP_XOR_QUAD_CurrentVersionRun_7f61 {
  strings:
    $key_7f61 = { 2c 0e [2] 08 00 [2] 23 2c [2] 0d 0e [2] 19 15 [2] 16 0f [2] 08 12 [2] 0a 13 [2] 11 15 [2] 0d 12 [2] 11 3d }

  condition:
    any of them
}