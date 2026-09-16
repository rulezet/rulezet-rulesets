rule TTP_XOR_QUAD_CurrentVersionRun_7043 {
  strings:
    $key_7043 = { 23 2c [2] 07 22 [2] 2c 0e [2] 02 2c [2] 16 37 [2] 19 2d [2] 07 30 [2] 05 31 [2] 1e 37 [2] 02 30 [2] 1e 1f }

  condition:
    any of them
}