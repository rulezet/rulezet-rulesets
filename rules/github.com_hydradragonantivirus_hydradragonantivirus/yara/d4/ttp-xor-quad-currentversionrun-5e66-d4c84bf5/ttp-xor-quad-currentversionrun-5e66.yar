rule TTP_XOR_QUAD_CurrentVersionRun_5e66 {
  strings:
    $key_5e66 = { 0d 09 [2] 29 07 [2] 02 2b [2] 2c 09 [2] 38 12 [2] 37 08 [2] 29 15 [2] 2b 14 [2] 30 12 [2] 2c 15 [2] 30 3a }

  condition:
    any of them
}