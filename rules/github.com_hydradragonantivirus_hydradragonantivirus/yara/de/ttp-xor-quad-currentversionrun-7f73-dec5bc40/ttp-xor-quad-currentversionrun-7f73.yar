rule TTP_XOR_QUAD_CurrentVersionRun_7f73 {
  strings:
    $key_7f73 = { 2c 1c [2] 08 12 [2] 23 3e [2] 0d 1c [2] 19 07 [2] 16 1d [2] 08 00 [2] 0a 01 [2] 11 07 [2] 0d 00 [2] 11 2f }

  condition:
    any of them
}