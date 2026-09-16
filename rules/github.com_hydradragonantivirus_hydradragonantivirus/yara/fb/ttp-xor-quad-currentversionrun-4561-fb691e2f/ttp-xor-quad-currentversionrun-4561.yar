rule TTP_XOR_QUAD_CurrentVersionRun_4561 {
  strings:
    $key_4561 = { 16 0e [2] 32 00 [2] 19 2c [2] 37 0e [2] 23 15 [2] 2c 0f [2] 32 12 [2] 30 13 [2] 2b 15 [2] 37 12 [2] 2b 3d }

  condition:
    any of them
}