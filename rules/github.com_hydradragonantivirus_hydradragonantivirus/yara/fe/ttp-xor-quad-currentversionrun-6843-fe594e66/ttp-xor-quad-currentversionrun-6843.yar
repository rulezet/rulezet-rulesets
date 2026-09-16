rule TTP_XOR_QUAD_CurrentVersionRun_6843 {
  strings:
    $key_6843 = { 3b 2c [2] 1f 22 [2] 34 0e [2] 1a 2c [2] 0e 37 [2] 01 2d [2] 1f 30 [2] 1d 31 [2] 06 37 [2] 1a 30 [2] 06 1f }

  condition:
    any of them
}