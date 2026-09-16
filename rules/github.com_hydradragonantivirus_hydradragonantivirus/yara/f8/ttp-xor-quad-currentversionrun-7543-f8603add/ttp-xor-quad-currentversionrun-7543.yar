rule TTP_XOR_QUAD_CurrentVersionRun_7543 {
  strings:
    $key_7543 = { 26 2c [2] 02 22 [2] 29 0e [2] 07 2c [2] 13 37 [2] 1c 2d [2] 02 30 [2] 00 31 [2] 1b 37 [2] 07 30 [2] 1b 1f }

  condition:
    any of them
}