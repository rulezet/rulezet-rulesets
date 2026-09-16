rule TTP_XOR_QUAD_CurrentVersionRun_6d61 {
  strings:
    $key_6d61 = { 3e 0e [2] 1a 00 [2] 31 2c [2] 1f 0e [2] 0b 15 [2] 04 0f [2] 1a 12 [2] 18 13 [2] 03 15 [2] 1f 12 [2] 03 3d }

  condition:
    any of them
}