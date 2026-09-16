rule TTP_XOR_QUAD_CurrentVersionRun_6b43 {
  strings:
    $key_6b43 = { 38 2c [2] 1c 22 [2] 37 0e [2] 19 2c [2] 0d 37 [2] 02 2d [2] 1c 30 [2] 1e 31 [2] 05 37 [2] 19 30 [2] 05 1f }

  condition:
    any of them
}