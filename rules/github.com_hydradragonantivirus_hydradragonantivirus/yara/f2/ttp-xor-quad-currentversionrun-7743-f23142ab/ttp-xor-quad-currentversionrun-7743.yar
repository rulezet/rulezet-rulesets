rule TTP_XOR_QUAD_CurrentVersionRun_7743 {
  strings:
    $key_7743 = { 24 2c [2] 00 22 [2] 2b 0e [2] 05 2c [2] 11 37 [2] 1e 2d [2] 00 30 [2] 02 31 [2] 19 37 [2] 05 30 [2] 19 1f }

  condition:
    any of them
}