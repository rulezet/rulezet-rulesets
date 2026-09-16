rule TTP_XOR_QUAD_CurrentVersionRun_7243 {
  strings:
    $key_7243 = { 21 2c [2] 05 22 [2] 2e 0e [2] 00 2c [2] 14 37 [2] 1b 2d [2] 05 30 [2] 07 31 [2] 1c 37 [2] 00 30 [2] 1c 1f }

  condition:
    any of them
}